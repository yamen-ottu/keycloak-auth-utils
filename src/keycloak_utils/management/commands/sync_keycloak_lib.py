import logging

from django.core.management.base import BaseCommand
from keycloak import KeycloakConnectionError

from django.conf import settings

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
            "--clients",
            nargs="+",
            type=str,
            required=False,
            help="List of clients to create in the specified realm.",
        )

    def handle(self, *args, **options):

        clients = options["clients"]

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
            # Await the base init of kc
            if run_keycloak_base:
                base_sync_result = current_app.send_task('keycloak_utils.sync.run_sync_routine_by_class_name',
                                                         args=(
                                                                kc_admin_config,
                                                               "KeycloakBase",
                                                               options["realm_name"],
                                                               clients,
                                                               )
                                                         )
                base_sync_result.get()

            if run_keycloak_role:
                current_app.send_task('keycloak_utils.sync.run_sync_routine_by_class_name',
                                      args=(
                                              kc_admin_config,
                                             "KeycloakRole",
                                            )
                                      )
                logger.info("Keycloak Role sync routine completed.")

            if run_keycloak_permissions:
                current_app.send_task('keycloak_utils.sync.run_sync_routine_by_class_name',
                                      args=(
                                              kc_admin_config,
                                             "KeycloakPermission",
                                            )
                                      )
                logger.info("Keycloak Permission sync routine completed.")

            if run_keycloak_user:
                current_app.send_task('keycloak_utils.sync.run_sync_routine_by_class_name',
                                      args=(
                                              kc_admin_config,
                                             "KeycloakUser",
                                            )
                                      )
                logger.info("Keycloak User sync routine completed.")

        except KeycloakConnectionError as e:
            logger.error(
                "unsuccessful connection attempt to server please make sure that keycloack is running on provided url and verify provided credentials"
            )

            # logger.info("KeycloakRole routine completed.")
