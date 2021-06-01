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


    @expose("/create_ta_user/", methods=["POST"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def test_user_creation(self) -> Response:
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
        data = request.json # json.loads(request.json)
        role_name = data['username']

        datasourceIds = data['datasourceIds'].split(',')
        pns = []
        for id in datasourceIds:
          pns.append('datasource access on [Tracking].[' + data['username'] + '](id:' + id + ')')
        
        #perm_name = 'datasource access on [Tracking (MySQL)].[' + data['username'] + '](id:' + data['datasourceId'] + ')'


        role = sm.add_role(role_name)
        pvms = sm.get_session.query(PermissionView).all()
        #pvms = [p for p in pvms if p.permission and p.view_menu]

        role.permissions = []
        for permission_view in pvms:
          for perm_name in pns:
            if self.custom_pvm_check(permission_view, perm_name):
              role.permission.append(permission_view)
              break


        #role.permissions = [
        #    permission_view for permission_view in pvms if self.custom_pvm_check(permission_view, perm_name)
        #]
        sm.get_session.merge(role)
        sm.get_session.commit()

        role_names = ['Gamma', role_name]
        user = sm.add_user(data['username'], data['username'], "user", data['username'] + "@test.at", list(map(lambda rn:sm.find_role(rn), role_names)), password=data['password'])
        sm.get_session.commit()
        return self.response(200, id=user.id)
