import socket
import threading
from functools import partial
import msgpack
import logging
import time
import pika
from pika.exceptions import (
    AMQPConnectionError,
    AMQPChannelError,
    ConnectionClosedByBroker,
)
from django.conf import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KeycloakEventHandler:
    @staticmethod
    def process_message(event_data):
        from .strategies import EventStrategyFactory

        logger.info(f"the data is {event_data} type is {type(event_data)}")

        operation_type = event_data["data"]["operation_type"].split(".")[0]
        event_type = event_data.get("data", {}).get("operation_type", "").split(".")[1]

        if (
            "user_id" in event_data["data"].get("operation_information", {}).keys()
            and (operation_type == "ASSIGN" or operation_type == "REMOVE")
            and event_type == "Role"
        ):
            operation_type = "UPDATE"
            event_type = "User"

        strategy = EventStrategyFactory.create_strategy(event_type)

        if strategy:
            logger.info("the strat in consumer is: {}".format(strategy))
            strategy.process(event_data, operation_type, event_type)
            return True
        else:
            logger.warning(f"Unknown event type: {event_type}, {event_data} not parsed")

class KeycloakEventConsumer(KeycloakEventHandler):
    def __init__(self):
        self.should_stop = threading.Event()
        self.connection = None
        self.channel = None
        self.url = settings.RABBITMQ_URL
        self.main_exchange = "eventbus.exchange"
        self.dlx_exchange = "eventbus.exchange.dlx"
        self.user_sync_ttl = 900000
        self.dlx_ttl = 100000
        self.queue_reg = self.QueueRegistry()
        self.register_queue = partial(self.queue_reg.register_queue)

    class QueueRegistry:
        """A registry for managing queues and their configurations."""
        settings_queue = settings.KC_UTILS_KC_REALM.replace('.', '_')
        def __init__(self):
            self._registry = {}
            if self.settings_queue:
                self.register_queue(f"users.{self.settings_queue}", f"eventbus.users.{self.settings_queue}")

        def register_queue(self, queue_name, routing_key="#"):
            if queue_name in self._registry:
                logger.warning(f"Queue '{queue_name}' is already registered.")
                return
            self._registry[queue_name] = {"queue": queue_name, "routing_key": routing_key}

        def unregister_queue(self, queue_name):
            if queue_name not in self._registry:
                raise KeyError(f"Queue '{queue_name}' is not registered.")
            del self._registry[queue_name]

        def get_queue(self, queue_name):
            return self._registry.get(queue_name, None)

        def list_queues(self):
            return self._registry


    def on_queue_declared(self, method_frame):
        queue_name = method_frame.method.queue
        logger.info(f"Queue {queue_name} declared")
        exception_map = {
            AMQPConnectionError: "Connection error",
            AMQPChannelError: "Channel error",
            ConnectionClosedByBroker: "Connection closed by broker",
        }
        try:
            self.channel.basic_consume(
                queue=queue_name, on_message_callback=self.handle_message
            )
        except Exception as e:
            message = exception_map.get(type(e), "Unexpected error")
            logger.error(f"{message}: {e}")
            self.retry_connect()

    def stop(self):
        self.should_stop.set()
        if self.channel and self.channel.is_open:
            self.connection.close()
        logger.info("Stopped consuming messages")

    def reject_callback(self, ch, method, properties, body):
        logger.info(f"Rejecting message: {self.decode_event(body)}")
        ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)

    @staticmethod
    def decode_event(body):
        return msgpack.unpackb(body, raw=False)

    def handle_message(self, ch, method, properties, body):
        try:
            event_data = self.decode_event(body)
            self.process_message(event_data)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            logger.exception(f"Error processing message: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def establish_connection(self):
        """Establish connection using pika.SelectConnection."""
        parameters = pika.URLParameters(self.url)
        self.connection = pika.SelectConnection(
            parameters=parameters,
            on_open_callback=self.on_connection_open,
            on_open_error_callback=self.on_connection_error,
            on_close_callback=self.on_connection_close,
        )
        try:
            self.connection.ioloop.start()
        except KeyboardInterrupt:
            self.stop()

    def retry_connect(self):
        attempt = 1
        max_retries = 10
        while attempt <= max_retries:
            logger.info(f"Reconnection attempt {attempt}...")
            try:
                self.establish_connection()
            except Exception as e:
                logger.error(f"Failed to initialize connection: {e}, retrying...")
                time.sleep(2)
                attempt += 1
            else:
                break
        logger.error(
            f"Maximum reconnection attempts reached. Exiting... number of attempts is {attempt}"
        )

    def on_connection_open(self, connection):
        logger.info("Connection opened")
        self.connection.channel(on_open_callback=self.on_channel_open)

    def on_connection_error(self, connection, error):
        logger.error(f"Connection error: {error}")
        self.retry_connect()

    def on_connection_close(self, connection, reason):
        logger.warning(f"Connection closed: {reason}")
        self.retry_connect()


    def on_channel_open(self, channel):
        """Callback when channel is successfully opened."""
        logger.info("Channel opened")
        self.channel = channel
        for _,queue_params in self.queue_reg.list_queues().items():
            self.setup_queue_and_dlx(queue_params)

    def setup_queue_and_dlx(self, params: dict):
        queue =  params["queue"]
        routing_key = params["routing_key"]
        dlx_queue = f"{queue}-dlx"
        dlx_routing_key = f"{routing_key}-dlx"

        try:

            self.channel.exchange_declare(
                exchange=self.main_exchange, exchange_type="topic", durable=True
            )
            self.channel.exchange_declare(
                exchange=self.dlx_exchange, exchange_type="topic", durable=True
            )

            self.channel.queue_declare(
                queue=queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": self.dlx_exchange,
                    "x-dead-letter-routing-key": dlx_queue,
                    "x-message-ttl": self.user_sync_ttl,
                },
                callback=self.on_queue_declared,
            )

            self.channel.queue_bind(
                exchange=self.main_exchange,
                queue=queue,
                routing_key=routing_key,
            )

            self.channel.queue_declare(
                queue=dlx_queue,
                durable=True,
                arguments={"x-message-ttl": self.dlx_ttl},
                callback=self.on_queue_declared,
            )
            self.channel.queue_bind(
                exchange=self.dlx_exchange,
                queue=dlx_queue,
                routing_key=dlx_routing_key,
            )

            self.channel.basic_qos(prefetch_count=1)

        except socket.gaierror as e:
            logger.error(f"DNS resolution error while connecting to RabbitMQ: {e}")

        except Exception as e:
            logger.error(f"connection error {e}")




class KeycloakEventAPI(KeycloakEventHandler):
    ...
