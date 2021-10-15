# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import logging
#import json

from flask import Response, request
from flask_appbuilder import expose
from flask_appbuilder.api import BaseApi, safe
from flask_appbuilder.security.decorators import permission_name, protect
from flask_appbuilder.security.sqla.models import PermissionView
from flask_wtf.csrf import generate_csrf

from superset import security_manager as sm
from superset.extensions import event_logger

logger = logging.getLogger(__name__)

class SecurityRestApi(BaseApi):
    resource_name = "security"
    allow_browser_login = True
    openapi_spec_tag = "Security"

    @expose("/csrf_token/", methods=["GET"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def csrf_token(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        return self.response(200, result=generate_csrf())

    def custom_pvm_check(self, pvm: PermissionView, perm_name: str) -> bool:
        return str(pvm) == perm_name

    
    def create_role(self, role_name, datasourceIds, datasourceNames, isUser) -> None:
      pns = []
      for idx, id in enumerate(datasourceIds):
        pns.append('datasource access on [Tracking].[' + datasourceNames[idx] + '](id:' + id + ')')

      if isUser:
        pns.append('can write on Dataset')
        pns.append('can read on Dataset')
        pns.append('menu access on Dataset')
        pns.append('can save on Datasource')

      role = sm.add_role(role_name)
      pvms = sm.get_session.query(PermissionView).all()

      role.permissions = []
      for permission_view in pvms:
        for perm_name in pns:
          if self.custom_pvm_check(permission_view, perm_name):
            role.permissions.append(permission_view)
            break

      sm.get_session.merge(role)
      sm.get_session.commit()


    @expose("/create_ta_user/", methods=["POST"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def ta_user_creation(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        data = request.json
        role_name = ''

        # admin, user, sub
        if data['type'] == 'admin':
          role_name = 'Admin'
        elif data['type'] == 'user':
          role_name = data['key']
        elif data['type'] == 'sub':
          role_name = data['key'] + '_sub'

        role = sm.find_role(role_name)

        if role is None:
          datasourceIds = data['datasourceIds'].split(',')
          datasourceNames = data['datasourceNames'].split(',')
          isUser = data['type'] = 'user'
          self.create_role(role_name, datasourceIds, datasourceNames, isUser)
        
        role_names = [role_name]
        if role_name != 'Admin':
          role_names.append('Gamma')

        user = sm.add_user(data['username'], 'DS2G', "User", data['email'], list(map(lambda rn:sm.find_role(rn), role_names)), password=data['password'])
        sm.get_session.commit()
        return self.response(200, id=user.id)

    @expose("/delete_ta_user/", methods=["POST"]) #DELETE
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def ta_user_deletion(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        data = request.json
        user = sm.find_user(data['username'])

        if user is not None:
          try:
            sm.get_session.delete(user)
            sm.get_session.commit()
          except SQLAlchemyError as ex:  # pragma: no cover
            sm.get_session.rollback()
            raise DAODeleteFailedError(exception=ex)

        return self.response(200)