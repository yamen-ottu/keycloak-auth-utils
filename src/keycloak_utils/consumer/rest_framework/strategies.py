import logging
from abc import ABC, abstractmethod
from typing import Type, Optional
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.apps import apps
from django.contrib.contenttypes.models import ContentType

from ...contrib.django.conf import KC_UTILS_KC_CLIENT_ID

logger = logging.getLogger("keycloak_event_consumer")
User = get_user_model()


class EventStrategy(ABC):
    ms_name = KC_UTILS_KC_CLIENT_ID

    def process(self, event_data, operation_type, event_type):
        if not self._validate_event(event_data):
            return

        operation_strategy = self._get_operation_strategy(operation_type)
        event_info = self._get_event_info(event_data["data"], event_type)
        if event_info is None:
            return
        operation_strategy(*event_info)

    def _validate_event(self, event_data):
        if "operation_information" not in event_data["data"].keys():
            logger.warning(
                f"the event data that failed with no operation_information key is {event_data}"
            )
            return False

        return True

    @staticmethod
    def _get_model_class(app_label: str, model_name: str) -> Optional[Type]:
        """Fetch the model class dynamically."""
        try:
            return apps.get_model(app_label, model_name)
        except Exception as e:
            logger.error(f"Error fetching model {app_label}.{model_name}: {e}")
            return None

    @staticmethod
    def _get_content_type_for_model(model: Type) -> ContentType:
        """Fetch the content type for a given model."""
        return ContentType.objects.get_for_model(model)

    @staticmethod
    def _handle_groups(roles):
        from django.contrib.auth.models import Group

        for group_name in roles:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                logger.info(f"Group '{group_name}' created successfully")
            else:
                logger.info(f"Group '{group_name}' already exists")

    @staticmethod
    def _handle_default(*args):
        logger.warning(f"Unknown operation")

    def _get_event_info(self, event_data, event_type):
        event_strategy_map = {
            "Permission": self._get_permission_info,
            "Role": self._get_role_info,
            "User": self._get_user_info,
        }
        return event_strategy_map[event_type](event_data)

    def _get_permission_info(self, event_data):
        if event_data["Client_Name"] != self.ms_name:
            return
        operation_info = event_data["operation_information"]
        policies = operation_info["apply_policy"]
        groups = [policy.replace("Policy", "") for policy in policies]
        permission_info = operation_info["name"]
        try:
            permission_name = operation_info["description"].split(".")[-1]
            permission_codename = permission_info.split(".")[2]
            permission_app = permission_info.split(".")[0]
            permission_model = permission_info.split(".")[1]
            return (
                permission_app,
                permission_codename,
                permission_model,
                permission_name,
                groups,
            )
        except KeyError as ke:
            logger.error(
                f"the permission info {permission_info} is not formatted correctly, the format should be app.model.codename"
            )
            raise ke

    def _get_role_info(self, event_data):
        role = event_data["operation_information"]
        if role["client"] != self.ms_name:
            return
        group_name = role["role_name"]
        role_id = role["role_id"]
        return group_name, role_id

    def _get_user_info(self, event_data):
        user = event_data["operation_information"]
        email = user["email"]
        firstname = user["firstName"]
        lastname = user["lastName"]
        username = user["username"]
        enabled = user["enabled"]
        roles = user["roles"]
        payout_roles = roles.get(self.ms_name, []) if isinstance(roles, dict) else []
        # payout_roles += user.get("roles_added", {}).get(self.ms_name, [])
        roles_names = [role["name"] for role in payout_roles]
        return email, username, firstname, lastname, roles_names, enabled

    @abstractmethod
    def _handle_create(self, *args): ...

    @abstractmethod
    def _handle_update(self, *args): ...

    @abstractmethod
    def _handle_delete(self, *args): ...

    def _get_operation_strategy(self, operation_type):
        if operation_type == "ASSIGN":
            operation_type = "CREATE"
        strategies = {
            "CREATE": self._handle_create,
            "UPDATE": self._handle_update,
            "DELETE": self._handle_delete,
        }
        return strategies.get(operation_type, self._handle_default)





class RoleEventStrategy(EventStrategy):
    def __init__(self):
        super().__init__()
        # self.kc_role = KeycloakRole()

    def _handle_create(self, group_name, role_id):
        group = Group.objects.create(name=group_name)
        # self.kc_role.get_or_create_policy(group, role_id)

    def _handle_update(self): ...

    def _handle_delete(self, group_name, *args):
        group = Group.objects.filter(name=group_name).delete()
        # self.kc_role.delete_policy(group)


class UserEventStrategy(EventStrategy):
    def __init__(self):
        super().__init__()

    def _handle_create(self, email, username, firstname, lastname, roles, enabled):
        user = User.objects.create(
            username=username, first_name=firstname, last_name=lastname, email=email
        )
        logger.info(f"created user {user}")

    def _handle_update(self, email, username, firstname, lastname, roles, enabled):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            logger.info(f"user {username} does not exist")
            return
        user.username = username
        user.first_name = firstname
        user.last_name = lastname
        user.is_active = enabled

        user_groups = Group.objects.filter(name__in=roles)
        user.groups.set(user_groups)
        user.save()

    def _handle_delete(self, *args): ...


class PermissionEventStrategy(EventStrategy):

    def _handle_create(
        self,
        permission_app,
        permission_codename,
        permission_model,
        permission_name,
        groups_names,
    ):
        try:
            content_type = ContentType.objects.get(
                app_label=permission_app, model=permission_model.lower()
            )
        except ContentType.DoesNotExist:
            logger.warning(
                f"no content type match {permission_app} and {permission_model}... breaking"
            )
            return
        except Exception as e:
            logger.error(e)
            return

        permission, _ = Permission.objects.get_or_create(
            content_type=content_type,
            codename=permission_codename,
        )

        self._update_groups_perms(permission, groups_names)

    def _handle_update(
        self,
        permission_app,
        permission_codename,
        permission_model,
        permission_name,
        groups_names,
    ):
        logger.info(
            f"Updating permission {permission_codename} in {permission_app} related group"
        )

        try:
            permission = Permission.objects.get(
                codename=permission_codename, content_type__app_label=permission_app
            )
        except Permission.DoesNotExist:
            logger.info(f"Permission {permission_codename} is not registered")
            return

        self._update_groups_perms(permission, groups_names)

    def _update_groups_perms(self, permission, groups_names):
        add_perm_groups = Group.objects.filter(name__in=groups_names).exclude(
            permissions=permission
        )
        remove_perm_groups = Group.objects.filter(permissions=permission).exclude(
            name__in=groups_names
        )

        if remove_perm_groups:
            list(
                map(
                    lambda group: group.permissions.remove(permission),
                    remove_perm_groups,
                )
            )
            logger.info(
                f"Removed permission {permission} to groups {remove_perm_groups}"
            )
        else:
            logger.info("no groups in the list of groups doesnt poses the permission")

        if add_perm_groups:
            list(
                map(
                    lambda group: group.permissions.add(permission),
                    add_perm_groups,
                )
            )
            logger.info(f"Added permission {permission} from groups {add_perm_groups}")
        else:
            logger.info("No groups need this permission removed.")

    def _handle_delete(self): ...


class EventStrategyFactory:
    @staticmethod
    def create_strategy(event_type):
        logger.info(f"the event_type in the strategy  factory is {event_type}")
        event_strategy_map = {
            "Permission": PermissionEventStrategy,
            "Role": RoleEventStrategy,
            "User": UserEventStrategy,
        }

        if event_type not in event_strategy_map.keys():
            return False

        return event_strategy_map[event_type]()

