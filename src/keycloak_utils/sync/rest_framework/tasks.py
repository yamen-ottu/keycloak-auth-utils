import importlib
import logging

from celery import shared_task

from . import kc_admin

logger = logging.getLogger(__name__)


@shared_task(name="keycloak_utils.sync.run_sync_routine_by_class_name")
def run_sync_routine_by_class_name(config, class_name, *args):
    if class_name == "KeycloakBase":
        config.pop("realm_name")
    try:
        logger.info("Initializing KeycloakAdmin instance...")
        kc_admin.initialize(**config)
        logger.info("KeycloakAdmin initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize KeycloakAdmin: {e}")
        raise e

    try:
        class_path = f"keycloak_utils.sync.rest_framework.core.{class_name}"
        module_name, class_name = class_path.rsplit('.', 1)
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        instance = cls(*args)
        instance.run_routine()
        logger.info(f"Successfully ran routine for {class_name}.")
    except Exception as e:
        logger.error(f"Error running routine for {class_name}: {e}")
        raise e