# Keycloak Utils Configuration and Usage Guide

This document outlines the necessary configuration changes for the Keycloak utilities and provides examples for syncing and consuming data in the application. The configuration section explains why each setting is needed and its default value. The usage examples demonstrate the two primary states of using the package: sync and consume.

---

## **Configuration Settings**

These environment variables are required for integrating Keycloak utilities into your application. Each variable serves a specific purpose in ensuring smooth communication between your application and the Keycloak server.

### **Key Configuration Variables**

| Environment Variable         | Default Value                | Description                                                                                                   |
|------------------------------|------------------------------|---------------------------------------------------------------------------------------------------------------|
| `KC_UTILS_KC_SERVER_URL`     | `https://sso.ottu.dev/auth/` | The base URL of the Keycloak server. Required for making API requests.                                        |
| `KC_UTILS_KC_REALM`          | `syncertest.ottu.dev`        | The realm used to manage users, groups, and roles.                                                            |
| `KC_UTILS_KC_CLIENT_ID`      | `payout`                     | The client ID registered in the Keycloak realm.                                                               |
| `KC_UTILS_KC_CLIENT_SECRET`  | ``                           | The client secret used for authentication.                                                                    |
| `KC_UTILS_KC_ADMIN_USER`     | ``                           | Admin username for Keycloak.                                                                                  |
| `KC_UTILS_KC_ADMIN_PASSWORD` | ``                           | Admin password for authentication.                                                                            |
| `KC_UTILS_KC_ADMIN_REALM`    | `master`                     | The admin realm where management operations are performed.                                                    |
| `KC_UTILS_KC_ADMIN_ID`       | `admin-cli`                  | The admin client ID used for administrative tasks.                                                            |
| `RABBITMQ_URL`               | ``                           | The RabbitMQ url.                                                                                             |
| `KC_UTILS_CREATE_QUEUES`     | `{}`                         | The dictionary of queues that needs to be created keys are types, values are lists of queue names.            |
| `KC_UTILS_SYNC_QUEUES`        | `{}`                         | The dictionary of queues that needs to be created and synced keys are types, values are lists of queue names. |

### **Why These Settings Are Necessary**

- **`KC_UTILS_KC_SERVER_URL`:** This is the entry point for all Keycloak operations, allowing the application to connect to the correct Keycloak instance.
- **`KC_UTILS_KC_REALM`:** Realms isolate different user bases and configurations. Using a specific realm ensures the application operates within the intended scope.
- **`KC_UTILS_KC_CLIENT_ID` and `KC_UTILS_KC_CLIENT_SECRET`:** These credentials authenticate the application to perform operations on behalf of the specified client.
- **`KC_UTILS_KC_ADMINRABBITMQ_URL_*`:** These settings provide administrative access to manage users, roles, and permissions in the Keycloak server.

---

## **Usage Examples**

### **1. Syncing Keycloak Roles, Users, and Permissions**
The `sync` command synchronizes Keycloak roles, users, and permissions with your Django application. Below is an example command and a description of its options.
#### **example command file**
```python
import logging

from django.core.management.base import BaseCommand
from keycloak import KeycloakConnectionError

from django.conf import settings

from keycloak_utils.sync.rest_framework.static import *

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync Keycloak roles to Django groups and assign permissions"

    def add_arguments(self, parser):
        parser.add_argument(
            "-migrate-groups",
            action="store_true",
            help="Run KeycloakRole routine",
            default=False,
        )

        parser.add_argument(
            "-migrate-users",
            action="store_true",
            help="Migrate users from Django to Keycloak",
            default=False,
        )
        parser.add_argument(
            "-migrate-permissions",
            action="store_true",
            help="Migrate permissions from Django to Keycloak",
            default=False,
        )
        parser.add_argument(
            "-migrate-base",
            action="store_true",
            help="Migrate base from Django to Keycloak",
            default=False,
        )

        parser.add_argument(
            "--server-url",
            type=str,
            help="Keycloak server URL (overrides environment variable)",
            default=settings.KC_UTILS_KC_SERVER_URL,
        )
        parser.add_argument(
            "--admin-username",
            type=str,
            help="Keycloak admin ID (overrides environment variable)",
            default=settings.KC_UTILS_KC_ADMIN_USER,
        )
        parser.add_argument(
            "--admin-secret",
            type=str,
            help="Keycloak admin secret (overrides environment variable)",
            default=settings.KC_UTILS_KC_ADMIN_PASSWORD,
        )
        parser.add_argument(
            "--realm-name",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=settings.KC_UTILS_KC_REALM,
        )
        parser.add_argument(
            "--admin-id",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=settings.KC_UTILS_KC_ADMIN_ID,
        )
        parser.add_argument(
            "--admin-realm",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=settings.KC_UTILS_KC_ADMIN_REALM,
        )
        parser.add_argument(
            "--public-clients",
            nargs="+",
            type=str,
            required=False,
            help="List of clients to create in the specified realm.",
        )
        parser.add_argument(
            "--private-clients",
            nargs="+",
            type=str,
            required=False,
            help="List of clients to create in the specified realm.",
        )

    desired_models_perms_map = {}

    def handle(self, *args, **options):

        clients = {
            "private": options["private_clients"],
            "public": options["public_clients"],
        }

        kc_admin_config = {
            "server_url": options["server_url"],
            "username": options["admin_username"],
            "password": options["admin_secret"],
            "client_id": options["admin_id"],
            "user_realm_name": options["admin_realm"],
            "realm_name": options["realm_name"],
        }

        run_keycloak_role = options["migrate_groups"]
        run_keycloak_user = options["migrate_users"]
        run_keycloak_permissions = options["migrate_permissions"]
        run_keycloak_base = options["migrate_base"]
        from celery import current_app

        try:
            logger.info("Running Keycloak Sync routine...")

            # TODO: make this as a chord or a chain with groups instead of .get to block connection
            if run_keycloak_base:
                base_sync_result = current_app.send_task(
                    "keycloak_utils.sync.run_sync_routine_by_class_name",
                    args=(
                        kc_admin_config,
                        "KeycloakBase",
                        options["realm_name"],
                        clients,
                    ),
                )
                logger.info("Keycloak Base sync routine is delegated successfully.")
                base_sync_result.get()  # Await the base init of kc realm
                logger.info("Keycloak Base sync routine is complete.")

            if run_keycloak_role:
                current_app.send_task(
                    "keycloak_utils.sync.run_sync_routine_by_class_name",
                    args=(
                        kc_admin_config,
                        "KeycloakRole",
                    ),
                )
                logger.info("Keycloak Role sync routine is delegated successfully.")

            if run_keycloak_permissions:
                perms = (
                    self.desired_models_perms_map
                    if self.desired_models_perms_map
                    else {}
                )
                current_app.send_task(
                    "keycloak_utils.sync.run_sync_routine_by_class_name",
                    args=(
                        kc_admin_config,
                        "KeycloakPermission",
                        perms,
                    ),
                )
                logger.info(
                    "Keycloak Permission sync routine is delegated successfully."
                )

            if run_keycloak_user:
                current_app.send_task(
                    "keycloak_utils.sync.run_sync_routine_by_class_name",
                    args=(
                        kc_admin_config,
                        "KeycloakUser",
                    ),
                )
                logger.info("Keycloak User sync routine is delegated successfully.")

        except KeycloakConnectionError as e:
            logger.error(
                "unsuccessful connection attempt to server please make sure that keycloak is running on provided url and verify provided credentials"
            )

 ```
#### **DESIRED_MODELS_PERMS_MAP example**
override this value in order to pass the models and their desired perms that needs to be synced, defaults to all models and default perms
```python
CREATE = "add"
READ = "view"
UPDATE = "change"
DELETE = "delete"
CUSTOM = "custom"

CRUD_PERMISSIONS = [CREATE, READ, UPDATE, DELETE]

DESIRED_MODELS_PERMS_MAP = {
    "source.payoutsource": CRUD_PERMISSIONS,
    "account.merchantaccount": CRUD_PERMISSIONS,
    "approvify.approvalflow": CRUD_PERMISSIONS,
    "approvify.policyconfig": CRUD_PERMISSIONS,
    "approvify.resourcepolicy": CRUD_PERMISSIONS,
    "beneficiary.beneficiary": CRUD_PERMISSIONS,
    "beneficiary.beneficiaryaccount": CRUD_PERMISSIONS,
    "payout.payoutintent": [CREATE, UPDATE, DELETE],
    "approvify.sanction": [READ, UPDATE],
}

```
key is uniformed as {appname.modelname} and value is the set of permissions to sync
#### **example command:**
```bash
python manage.py sync_keycloak \
    --realm-name "synctest.ottu.dev" \
    --private-clients payout estate core \
    --public-clients frontend publictest \
    -migrate-groups \
    -migrate-users \
    -migrate-base \
    -migrate-permissions
```


#### **Options:**
- `-migrate-base`: Creates Keycloak realm and initialize it's base data.
- `-migrate-groups`: Synchronize Keycloak roles to Django groups.
- `-migrate-users`: Migrate users from Django to Keycloak.
- `-migrate-permissions`: Migrate permissions from Django to Keycloak.
- `--realm-name`: Specify the Keycloak realm to operate on.
- `--clients`: Specify the clients that needs to be created noting that core and frontend are created by default

### **2. Consumer**
The `consumer` command starts a consumer that receives keycloak events and handles them accordingly
#### **example command:**
```bash
python manage.py run_consumer
```
this command needs to register each queue to the consumer and will init the queue registery with the settings queue is KC_UTILS_KC_REALM_NAME env var is set

#### **example command file**
```python
import signal
import sys
import logging

from django.core.management.base import BaseCommand
from keycloak_utils.consumer.rest_framework.core import KeycloakEventConsumer

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run the Keycloak event consumer"

    def add_arguments(self, parser):
        parser.add_argument(
            "--users-queues",
            nargs="*",
            default=[],
            help="Space-separated list of user queues (e.g., user_queue1 user_queue2).",
        )
        parser.add_argument(
            "--payment-queues",
            nargs="*",
            default=[],
            help="Space-separated list of payment queues (e.g., payment_queue1 payment_queue2).",
        )
        parser.add_argument(
            "--general-queues",
            nargs="*",
            default=[],
            help="Space-separated list of general queues (e.g., general_queue1 general_queue2).",
        )
        parser.add_argument(
            "--users-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of user queues (e.g., user_queue1 user_queue2).",
        )
        parser.add_argument(
            "--payment-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of payment queues (e.g., payment_queue1 payment_queue2).",
        )
        parser.add_argument(
            "--general-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of general queues (e.g., general_queue1 general_queue2).",
        )

    queues_reg = []

    def handle(self, *args, **options):
        create_queues = {
            "users": options["users_queues"],
            "payment": options["payment_queues"],
            "general": options["general_queues"],
        }

        sync_queues = {
            "users": options["users_sync_queues"],
            "payment": options["payment_sync_queues"],
            "general": options["general_sync_queues"],
        }

        consumer = KeycloakEventConsumer()

        consumer.register_queue(create_queues, queue_status="create")
        consumer.register_queue(sync_queues, queue_status="sync")

        for queue in self.queues_reg:
            consumer.register_queue(*queue)

        consumer.establish_connection()

        def signal_handler(signum, frame):
            self.stdout.write(
                self.style.WARNING("Received shutdown signal. Stopping consumers...")
            )
            consumer.stop()
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.stdout.write(self.style.SUCCESS("Starting Keycloak event consumer"))
```
#### example queues_reg
first val is name second is routing key third is create or sync
```python    
queues_reg = [
    ("users.queuereg_ottu_dev", "eventbus.users.queuereg_ottu_dev", "create"),
    ("users.queuereg2_ottu_dev", "eventbus.users.queuereg2_ottu_dev", "sync"),
]
```
#### **example command:**
```bash
python manage.py run_consumer
python manage.py run_consumer --users-queues livetest --users-sync-queues livetestsync       
```
this needs to be run in each microservice and make sure to pass the KC_UTILS_KC_CLIENT_ID env var that specifies which microservice it is run on to pickup only according events 
override the queues_reg to define custom values where first arg is queue name second is routing key and third if sync or create

#### **adding your custom handler for custom events**
```python
class EventTypeStrategyClassFactory(BaseEventStrategyFactory):
    event_map = {
        "payment": PaymentEventStrategyFactory,
        "kc": KCEventStrategyFactory,
    }
```
this class's event_map needs to be updatesd with the key of the event and the value the class that shouldbe defined to handle such event
### **3. APIVIEW EventHandler **
#### **example view file**
```python
import logging

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import status
from rest_framework.response import Response
from keycloak_utils.consumer.rest_framework.core import KeycloakEventAPI
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


class ConsumerAPIView(APIView):
    @extend_schema(
        summary="Post JSON data to ConsumerAPI",
        description="This endpoint accepts a JSON payload and processes it.",
        request={
            "application/json": {
                "type": "object",
                "properties": {},
            }
        },
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                name="Valid Request Example",
                description="A sam  ple payload for the API",
                value={},
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        event_data = request.data
        try:
            processed = KeycloakEventAPI.process_message(event_data)
            if processed:
                return Response(
                    f"processed event {event_data} successfully!",
                    status=status.HTTP_200_OK,
                )
            return Response(
                f"processing event {event_data} failed please check logs!",
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"status": "error", "message": f"Failed to connect {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

```
this creates an apiview that accepts the event data as decoded json format for the app to handle in case of client having a low spec machine that doesnt support consumers 

