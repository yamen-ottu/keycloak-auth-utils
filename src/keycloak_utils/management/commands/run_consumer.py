import signal
import sys
import logging

from django.core.management.base import BaseCommand
from keycloak_utils.consumer.rest_framework.core import KeycloakEventConsumer

logger = logging.getLogger("keycloak_event_consumer")


class Command(BaseCommand):
    help = "Run the Keycloak event consumer"

    def handle(self, *args, **options):
        consumer = KeycloakEventConsumer()
        consumer.establish_connection()

        def signal_handler(signum, frame):
            self.stdout.write(
                self.style.WARNING("Received shutdown signal. Stopping consumers...")
            )
            consumer.stop()
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.stdout.write(self.style.SUCCESS("StartingKeycloak event consumer"))
