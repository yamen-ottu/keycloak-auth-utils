import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from itertools import chain
from typing import Any, Dict, Generator, List, Optional, cast

from django.apps import apps
from django.contrib.auth import get_user_model
from django.db.models import Q, QuerySet

from ...contrib.django.conf import KC_UTILS_KC_CLIENT_ID
from . import kc_admin
from .static import CRUD_PERMISSIONS

logger = logging.getLogger(__name__)


class KeycloakSync:
    def __post_init__(self):
        self.kc_client_id = self._get_obj_by_kc_key(
            kc_admin.get_clients, KC_UTILS_KC_CLIENT_ID, "clientId", "id"
        )
        if not self.kc_client_id:
            raise ValueError(
                f"Keycloak client ID ('{KC_UTILS_KC_CLIENT_ID}') not found in current realm"
            )
        self._generator = self._create_generator()
        self.formatter = self._Formatter(self)
        self.entity_fetchers_map = {
            "resource": kc_admin.get_client_authz_resources,
            "scope": kc_admin.get_client_authz_scopes,
            "permission": kc_admin.get_client_authz_permissions,
            "role": kc_admin.get_client_roles,
            "policy": kc_admin.get_client_authz_policies,
            "user": kc_admin.get_users,
        }

        self.entity_creators_map = {
            "resource": lambda json: kc_admin.create_client_authz_resource(
                self.kc_client_id, json, skip_exists=True
            ),
            "scope": lambda json: kc_admin.create_client_authz_scopes(
                self.kc_client_id, json
            ),
            "permission": lambda json: kc_admin.create_client_authz_scope_permission(
                json, self.kc_client_id
            ),
            "role": lambda json: kc_admin.create_client_role(
                self.kc_client_id, json, skip_exists=True
            ),
            "policy": lambda json: kc_admin.create_client_authz_role_based_policy(
                self.kc_client_id, json, skip_exists=True
            ),
            "user": lambda json: kc_admin.create_user(json),
        }

    class _Formatter:
        """
        Internal class to handle formatting strategies for resources and scopes.
        """

        def __init__(self, outer_instance: "KeycloakSync"):
            self.outer_instance = outer_instance

        def format_resource(self, model_name: str) -> Dict[str, Any]:
            """
            Returns a JSON structured Resource as (name, display_name).
            """
            model_name = model_name.title()
            app_label, model = model_name.split(".")
            formatted_resource = f"{app_label}.{model}"
            formatted_resource_display = f"{app_label}.{model}"
            resource_dict = {
                "name": formatted_resource,
                "displayName": formatted_resource_display,
            }
            return resource_dict

        def format_scope(self, perm) -> Dict[str, Any]:
            """
            Returns a JSON structured Scope as (name, display_name).
            """
            model = perm.content_type.model
            app_label = perm.content_type.app_label
            try:
                action = perm.name.split(" ")[1]
            except IndexError:
                action = perm.name.split("_")[1]

            formatted_auth_scope = f"{app_label}.{model}.{action}_{model}"
            formatted_auth_scope_display = (
                f"{formatted_auth_scope}.can_{action}_{model}"
            )
            scope_dict = {
                "name": formatted_auth_scope,
                "displayName": formatted_auth_scope_display,
            }
            return scope_dict

        def format_permission(self, perm, set_scope: bool = True) -> Dict[str, Any]:
            """
            Returns a JSON structured Permission as (name, description, scopes).
            """
            self.outer_instance: KeycloakPermission
            formatted_auth_scope, formatted_auth_scope_display = self.format_scope(
                perm
            ).values()
            formatted_auth_permission = f"{formatted_auth_scope}.perm"
            formatted_auth_perm_desc = formatted_auth_scope_display
            permission_dict = {
                "name": formatted_auth_permission,
                "description": formatted_auth_perm_desc,
                "scopes": [
                    self.outer_instance.current_scope_id,
                ],
                "type": "scope",
            }

            return permission_dict

        def format_role(self, group) -> Dict[str, Any]:
            name = group.name
            description = f"{name}Role"
            role_dict = {"name": name, "description": description}
            return role_dict

        def format_policy(self, group) -> Dict[str, Any]:
            self.outer_instance: KeycloakRole
            name = f"{group.name}Policy"
            description = f"{name}Policy"
            policy_dict = {
                "name": name,
                "description": description,
                "roles": [{"id": self.outer_instance.current_role}],
                "type": "role",
            }
            return policy_dict

        def format_user(self, user) -> Dict[str, Any]:
            username = user.username
            firstname = user.first_name
            lastname = user.last_name
            email = user.email
            user_dict = {
                "username": username,
                "firstName": firstname,
                "lastName": lastname,
                "email": email,
                "enabled": user.is_active,
                "emailVerified": user.is_active,
            }
            return user_dict

        def format_realm(self, realm_name):
            realm_dict = {
                "id": realm_name,
                "realm": realm_name,
                "enabled": True,
                "displayName": realm_name,
                "sslRequired": "external",
                "loginTheme": "ottu-light",
                "accountTheme": "ottu-light",
                "adminTheme": "ottu-light",
                "accessTokenLifespan": 900,
                "attributes": {"attributesEnabled": "true"},
                "eventsListeners": ["custom-event-listener", "jboss-logging"],
            }
            return realm_dict

        def format_protocol_mapper(self, client_name):
            audience_mapper_dict = {
                "name": client_name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "claim.name": client_name,
                    "id.token.claim": "true",
                    "included.client.audience": client_name,
                    "included.custom.audience": "",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                },
            }

            user_attr_mapper = {
                "name": client_name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {
                    "claim.name": client_name,
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "lightweight.claim": "true",
                    "userinfo.token.claim": "true",
                    "introspection.token.claim": "true",
                    "user.attribute": client_name,
                    "jsonType.label": "String",
                },
            }

            mapper_creators = {
                "audience": audience_mapper_dict,
                "user_attribute": user_attr_mapper,
            }
            return mapper_creators

        def format_client_scope(self, client_scope):
            client_scope_dict = {
                "name": client_scope,
                "description": client_scope,
                "type": "none" if client_scope != "timezone" else "default",
                "protocol": "openid-connect",
                "attributes": {
                    "display.on.consent.screen": "true",
                    "consent.screen.text": "",
                    "include.in.token.scope": False,
                    "gui.order": "",
                },
            }
            return client_scope_dict

        def format_client(self, client_data):
            self.outer_instance: KeycloakBase
            client_name, client_type = client_data
            base_payload = {
                "clientId": client_name,
                "name": client_name,
                "description": client_name,
                "enabled": True,
                "clientAuthenticatorType": "client-secret",
                "redirectUris": [f"https://{self.outer_instance.realm_name}/*"],
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "fullScopeAllowed": True,
                "attributes": {
                    "login_theme": "ottu-light",
                },
            }

            def public_client_payload(payload):
                payload |= {"publicClient": True}
                return payload

            def private_client_payload(payload):
                payload |= {
                    "publicClient": False,
                    "standardFlowEnabled": True,
                    "implicitFlowEnabled": False,
                    "directAccessGrantsEnabled": True,
                    "serviceAccountsEnabled": True,
                    "protocol": "openid-connect",
                    "fullScopeAllowed": True,
                    "authorizationServicesEnabled": True,
                    "serviceAccountsEnabled": True,
                    "authorizationSettings": {
                        "allowRemoteResourceManagement": True,
                        "decisionStrategy": "AFFIRMATIVE",
                        "policyEnforcementMode": "ENFORCING",
                    },
                }
                return payload

            client_type_mapper = {
                "public": public_client_payload,
                "private": private_client_payload,
            }

            return client_type_mapper[client_type](base_payload)

    def _jsonify(self, _object=None, strategy=None):
        """
        Convert the formatted permission into a JSON-friendly dictionary.
        """
        if not _object:
            raise ValueError("Object cannot be empty.")

        strategy_map = {
            "resource": self.formatter.format_resource,
            "scope": self.formatter.format_scope,
            "permission": self.formatter.format_permission,
            "role": self.formatter.format_role,
            "policy": self.formatter.format_policy,
            "user": self.formatter.format_user,
            "realm": self.formatter.format_realm,
            "protocol_mapper": self.formatter.format_protocol_mapper,
            "client_scope": self.formatter.format_client_scope,
            "client": self.formatter.format_client,
        }

        if strategy not in strategy_map:
            raise ValueError(
                f"Invalid strategy: {strategy}. please select one of {strategy_map.keys()}"
            )

        return strategy_map[strategy](_object)

    def _get_obj_by_kc_key(
        self,
        kc_admin_objs_getter,
        obj_value,
        fetch_key,
        return_key=None,
        use_admin=False,
    ):
        objects = (
            kc_admin_objs_getter(self.kc_client_id)
            if use_admin
            else kc_admin_objs_getter()
        )
        obj = next(
            (obj for obj in objects if obj.get(fetch_key) == obj_value),
            None,
        )

        return obj[return_key] if return_key and obj else obj

    @staticmethod
    def _get_permission_model():
        """
        Lazily retrieve the Permission model to avoid import errors.
        """
        from django.contrib.auth.models import Permission

        return Permission

    @staticmethod
    def _get_group_model():
        """
        Lazily retrieve the Permission model to avoid import errors.
        """
        from django.contrib.auth.models import Group

        return Group

    def _get_kc_entity_by_name(
        self, entity_name: str, entity_type: str
    ) -> Optional[Dict]:
        """
        Fetch the authorization entity (resource, scope, or permission) by its name.

        :param entity_type: The type of entity to fetch ('resources', 'scopes', or 'permissions').
        :param entity_name: The name of the entity to search for.
        :return: The matching entity if found, otherwise None.
        """

        if entity_type not in self.entity_fetchers_map:
            raise ValueError(
                f"Invalid entity type: {entity_type}. Must be one of {', '.join(self.entity_fetchers_map.keys())}."
            )
        fetcher_func = self.entity_fetchers_map[entity_type]
        key, use_admin = (
            ("username", False) if entity_name == "user" else ("name", True)
        )

        return self._get_obj_by_kc_key(
            fetcher_func, entity_name, key, use_admin=use_admin
        )

    def __create_kc_entity(self, json: Dict, entity_type: str):
        """
        Create an authorization entity (resource, scope, or permission) in Keycloak.

        :param json: The JSON payload with the entity details.
        :param entity_type: The type of entity to create ('resource', 'scope', 'permission').
        :raises ValueError: If the entity type is invalid.
        """

        if entity_type not in self.entity_creators_map:
            raise ValueError(
                f"Invalid entity type: {entity_type}. Must be one of {', '.join(self.entity_creators_map.keys())}."
            )

        return self.entity_creators_map[entity_type](json)

    def _get_or_create_kc_entity(
        self, json: Dict, entity_type: str, key="name"
    ) -> Optional[Dict]:

        entity_name = json[key]
        if (
            entity := self._get_kc_entity_by_name(entity_name, entity_type=entity_type)
        ) is not None:
            logger.info(f'{entity_type} {entity.get(key, "")} already exists.')

        else:
            entity = cast(Dict, self.__create_kc_entity(json, entity_type))
            logger.info(f"created {entity_type} {entity_name}.")

        if isinstance(entity, str):
            entity = self._get_or_create_kc_entity(json, entity_type)
        return entity

    @abstractmethod
    def _create_generator(self):
        raise NotImplementedError

    def _get_next_object(self):
        """
        Fetch the next permission from the generator.
        Returns None if no more permissions are available.
        """
        try:
            return next(self._generator)
        except StopIteration:
            return None

    @abstractmethod
    def run_routine(self):
        raise NotImplementedError


@dataclass
class KeycloakPermission(KeycloakSync):
    desired_models_perms_map: Dict[str, List] = field(default_factory=dict)
    _permission_generator: Generator[object, None, None] = field(init=False, repr=False)
    current_resource_id = None
    current_scope_id = None

    def __post_init__(self):
        """
        Validate that each desired model is a valid Django model associated with permissions.
        Initialize the permission generator.
        """
        super().__post_init__()

        self._validate_models()

    def _validate_models(self):
        """
        Ensure that all desired models are valid and associated with permissions.
        """
        Permission = self._get_permission_model()
        if not self.desired_models_perms_map:
            for perm in Permission.objects.all():
                content_type = perm.content_type
                perm_key = f"{content_type.app_label}.{content_type.model}"
                self.desired_models_perms_map[perm_key] = CRUD_PERMISSIONS
        for model_name in self.desired_models_perms_map.keys():
            try:
                app_label, model = model_name.split(".")
                apps.get_model(app_label, model)

            except ValueError:
                raise ValueError(
                    f"Model {model_name} string must be in the format 'app_label.ModelName'."
                )

            except LookupError:
                raise LookupError(f"Model '{model_name}' could not be found.")

            if not Permission.objects.filter(content_type__model=model):
                raise ValueError(
                    f"Model '{model_name}' does not have associated permissions."
                )

    def _model_registered_perms_generator(self, model_name, django_perms: QuerySet):
        registered_perms = self.desired_models_perms_map[model_name]
        query = Q()
        for registered_perm in registered_perms:
            query |= Q(codename__startswith=registered_perm)

        perms = django_perms.filter(query)
        if not perms:
            logger.warning(
                f"{model_name} does not have any of {registered_perms} permissions."
            )

        return perms

    def _create_generator(self):
        """
        Internal method to create a generator that fetches the desired permissions for each model.
        """
        Permission = self._get_permission_model()
        for model_name in self.desired_models_perms_map.keys():
            _, model = model_name.split(".")
            perms = Permission.objects.filter(content_type__model=model)

            self.create_kc_resource(model_name)

            perms = self._model_registered_perms_generator(model_name, perms)

            for perm in perms:
                yield perm

    def create_kc_resource(self, model):
        strategy = "resource"
        json_resource = self._jsonify(model, strategy=strategy)

        resource = self._get_or_create_kc_entity(json_resource, entity_type=strategy)
        self.current_resource_id = resource["_id"]

    def create_kc_scope(self, permission):
        json_scope = self._jsonify(permission, strategy="scope")
        scope = self._get_or_create_kc_entity(json_scope, entity_type="scope")

        resource = kc_admin.get_client_authz_resource(
            self.kc_client_id, self.current_resource_id
        )
        try:
            resource["scopes"] = resource.get("scopes", [])
            if not any(
                resource_scope["name"] == scope["name"]
                for resource_scope in resource["scopes"]
            ):
                resource["scopes"].append(scope)
                kc_admin.update_client_authz_resource(
                    self.kc_client_id, self.current_resource_id, resource
                )

                logger.info(
                    f'added scope {scope["name"]} to resource {resource["name"]}'
                )
            else:
                logger.info(
                    f'scope {scope["name"]} already exists in resource {resource["name"]}'
                )

        except Exception as e:
            logger.error(f"an error occured while creating authz scope {e}")
            raise e

        self.current_scope_id = scope["id"]

    def create_kc_permission(self, permission):
        json_perm = self._jsonify(permission, strategy="permission")

        _ = self._get_or_create_kc_entity(json_perm, entity_type="permission")

    def run_routine(self):
        while True:
            permission = self._get_next_object()
            if permission is None:
                break
            try:
                self.create_kc_scope(permission)

                self.create_kc_permission(permission)

            except ValueError as ve:
                logger.error(f"Skipping invalid permission: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing permission '{permission}': {e}")
                raise e


@dataclass
class KeycloakRole(KeycloakSync):
    current_role = None
    current_policy = None

    def _create_generator(self):
        """
        Internal method to create a generator that fetches Groups.
        """
        Group = self._get_group_model()
        groups = Group.objects.all()

        group: Group
        for group in groups:
            yield group

    def create_role(self, group):
        json_role = self._jsonify(group, strategy="role")
        role = self._get_or_create_kc_entity(json_role, entity_type="role")
        self.current_role = role["id"]

    def get_or_create_policy(self, group, role_id=None):
        if role_id:
            self.current_role = role_id
        json_policy = self._jsonify(group, strategy="policy")
        policy = self._get_or_create_kc_entity(json_policy, entity_type="policy")
        return policy

    def delete_policy(self, group):
        policy = self._get_kc_entity_by_name(group, entity_type="policy")
        if policy is None:
            logger.warning(f"the policy {policy} does not exist in keycloak")
            return
        policy_id = policy["id"]
        kc_admin.delete_client_authz_policy(self.kc_client_id, policy_id)

    def add_policies_to_permissions(self, group):
        permissions = group.permissions.all()

        for permission in permissions:
            json_scope = self._jsonify(permission, strategy="scope")
            scope = self._get_or_create_kc_entity(json_scope, entity_type="scope")

            self.current_scope_id = scope["id"]
            json_permission = self._jsonify(permission, strategy="permission")
            permission = self._get_or_create_kc_entity(
                json_permission, entity_type="permission"
            )
            json_policy = self._jsonify(group, strategy="policy")
            policy = self._get_or_create_kc_entity(json_policy, entity_type="policy")
            permission_policies = (
                kc_admin.get_client_authz_permission_associated_policies(
                    self.kc_client_id, permission["id"]
                )
            )

            if all(policy["name"] != p["name"] for p in permission_policies):
                perm_id = permission.pop("id")
                permission["scopes"] = json_permission["scopes"]
                permission_policies.append(policy)
                permission["policies"] = [
                    policy["id"] for policy in permission_policies
                ]
                kc_admin.update_client_authz_scope_permission(
                    permission, self.kc_client_id, perm_id
                )
                logger.info(
                    f'added {policy["name"]} to permission {permission["name"]}'
                )
            else:
                logger.info(
                    f'policy {policy["name"]} already exists in permission {permission["name"]}'
                )

    def run_routine(self):
        while True:
            group = self._get_next_object()
            if group is None:
                break

            try:
                self.create_role(group)
                self.get_or_create_policy(group)
                self.add_policies_to_permissions(group)
            except ValueError as ve:
                logger.error(f"Skipping invalid permission: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing group '{group}': {e}")
                raise e


@dataclass
class KeycloakUser(KeycloakSync):
    current_user = None

    def _create_generator(self):
        """
        Internal method to create a generator that fetches Groups.
        """
        User = get_user_model()
        users = User.objects.all()

        user: User
        for user in users:
            yield user

    def create_user(self, user):
        json_user = self._jsonify(user, strategy="user")
        user = self._get_or_create_kc_entity(
            json_user, entity_type="user", key="username"
        )
        self.add_tz_user_attr(user)
        self.current_user = user["id"]

    def add_tz_user_attr(self, user):
        timezone = [
            "Asia/Kuwait"
        ]  # TODO update based on real tz field and default to this if not available
        user |= {"attributes": {"timezone": timezone}}
        kc_admin.update_user(user["id"], user)

    def _add_superadmin_roles(self):
        admin_roles = ["manage-clients", "query-users", "create-client"]
        realm_manage_client_id = self._get_obj_by_kc_key(
            kc_admin.get_clients(),
            "realm-management",
            "id",
            "id",
        )
        superadmin_management_roles = [
            kc_admin.get_client_role(realm_manage_client_id, role)
            for role in admin_roles
        ]
        kc_admin.assign_client_role(
            self.current_user, realm_manage_client_id, superadmin_management_roles
        )
        superadmin_realm_role = kc_admin.get_realm_role("super_admin")
        kc_admin.assign_realm_roles(self.current_user, [superadmin_realm_role])

    def assign_user_roles(self, user):
        groups = user.groups.all()
        roles = []
        for group in groups:
            roles.append(kc_admin.get_client_role(self.kc_client_id, group.name))
        kc_admin.assign_client_role(self.current_user, self.kc_client_id, roles)
        if user.is_superuser:
            self._add_superadmin_roles()

    def run_routine(self):
        while True:
            user = self._get_next_object()
            if user is None:
                break

            try:
                self.create_user(user)
                self.assign_user_roles(user)
            except ValueError as ve:
                logger.error(f"Skipping user: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing user '{user}': {e}")
                continue


@dataclass
class KeycloakBase(KeycloakSync):
    realm_name: str
    clients: dict

    def __post_init__(self):
        self.formatter = self._Formatter(self)
        self._validate_clients()

    def _validate_clients(self):
        for clients_type in ["private", "public"]:
            """Validates and processes client list to ensure no duplicates."""
            clients = self.clients.get(f"{clients_type}", {}) or {}
            base_clients_dict = {"private": {"core"}, "public": {"frontend"}}
            base_clients = base_clients_dict[clients_type]
            filtered_clients = set(clients)

            duplicates = filtered_clients.intersection(base_clients)
            if duplicates:
                logger.warning(
                    f"The following clients are duplicates and will be ignored: {', '.join(duplicates)}"
                )

            self.clients[clients_type] = list(base_clients.union(filtered_clients))

    def create_realm(self):
        json_realm = self._jsonify(self.realm_name, strategy="realm")
        realm = kc_admin.create_realm(json_realm, skip_exists=True)
        logger.info(f"created realm {realm} successfully ")

        def update_up_config():
            up_config = kc_admin.get_realm_upconfig(self.realm_name)
            up_config |= {"unmanagedAttributePolicy": "ENABLED"}
            kc_admin.update_realm_upconfig(self.realm_name, up_config)

        update_up_config()
        kc_admin.connection.realm_name = self.realm_name

        client_scope_id = self.create_client_scope("timezone")
        self.create_client_protocol_mapper(
            "timezone", client_scope_id, mapper_type="user_attribute"
        )

    def create_client_protocol_mapper(
        self, client_name, client_scope_id, mapper_type="audience"
    ):
        protocol_mappers = self._jsonify(client_name, "protocol_mapper")
        kc_admin.create_client_scope_mapper(
            client_scope_id, protocol_mappers[mapper_type]
        )
        logger.info("created mapper {}".format(mapper_type))

    def create_client_scope(self, client_name):
        payload = self._jsonify(client_name, "client_scope")
        client_scope = kc_admin.create_client_scope(payload, skip_exists=True)
        logger.info(
            f"created client scope {client_name} of type {client_scope} successfully"
        )
        return client_scope

    def add_client_scope_to_client(self, client_id, client_scope_name="timezone"):
        client_scope_id = self._get_obj_by_kc_key(
            kc_admin.get_client_scopes, client_scope_name, "name", "id"
        )
        payload = {
            "realm": kc_admin.connection.realm_name,
            "client": client_id,
            "clientScopeId": client_scope_id,
        }
        resp = kc_admin.add_client_default_client_scope(
            client_id, client_scope_id, payload
        )
        return resp

    def create_client(self, client_name, client_type="private"):
        client_payload = self._jsonify([client_name, client_type], "client")
        client_id = kc_admin.create_client(client_payload, skip_exists=True)

        def update_resource_server():
            resource_server = kc_admin.get_client_resource_server(client_id)
            resource_server["decisionStrategy"] = "UNANIMOUS"
            kc_admin.update_client_resource_server(client_id, resource_server)

        if client_type == "private":
            update_resource_server()

        self.add_client_scope_to_client(client_id, "timezone")

        prefixed_client_name = f"{client_name}-service"
        client_scope_id = self.create_client_scope(prefixed_client_name)
        self.create_client_protocol_mapper(client_name, client_scope_id)
        self.add_client_scope_to_client(client_id, prefixed_client_name)

    def create_superadmin_role(self):
        role_representation = {
            "name": "super_admin",
            "description": "super admin",
        }
        kc_admin.create_realm_role(role_representation, skip_exists=True)
        logger.info("created super_admin role")

    def run_routine(self):
        try:
            self.create_realm()
            for client, client_type in chain.from_iterable(
                ((client, client_type) for client in clients)
                for client_type, clients in self.clients.items()
            ):
                self.create_client(client, client_type=client_type)
            self.create_superadmin_role()
        except ValueError as ve:
            logger.error(f"Value Error: {ve}")
        except Exception as e:
            logger.error(f"Error: {e}")
            raise e
