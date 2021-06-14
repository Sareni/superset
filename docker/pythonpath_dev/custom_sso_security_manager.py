import logging
import requests
import json
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import AuthOAuthView
from flask_appbuilder.baseviews import expose
import time
from flask import redirect


class CustomSsoAuthOAuthView(AuthOAuthView):

    @expose("/logout/")
    def logout(self, provider="ownauth", register=None):
        logging.debug("[XXX] Logging out...")
        ret = super().logout()
        time.sleep(1)
        logging.debug("[XXX] Successfully logged out!")
        return redirect('test.zenpa.at')

class CustomSsoSecurityManager(SupersetSecurityManager):

    authoauthview = CustomSsoAuthOAuthView

    def oauth_user_info(self, provider, response=None):
        logging.debug("Oauth2 provider: {0}.".format(provider))

        if provider == 'auth0':
           
            #res = self.appbuilder.sm.oauth_remotes[provider].get('https://dev-x4orscvo.eu.auth0.com/userinfo')
            #print(res)
            #if res.status != 200:
            #    logger.error('Failed to obtain user info: %s', res.data)
            #    return
            #me = res.data
            #logger.debug(" user_data: %s", me)
            #prefix = 'Superset'

            resp = requests.get('https://dev-x4orscvo.eu.auth0.com/userinfo', headers={ 'Authorization': 'Bearer ' + self.oauth_tokengetter()[0]}).content
            userinfo =  json.loads(resp.decode('utf-8'))
            #logging.debug(" user_data: %s", userinfo)
            
            return {
                'username' : userinfo['email'], #
                #'name' : userinfo['name'], #me['name']
                #'email' : userinfo['email'], #me['email']
                #'first_name': 'first_name', #me['given_name'],
                #'last_name': 'last_name', #me['family_name'],
            }

        if provider == 'ownauth':

            resp = requests.get('http://test.zenpa.at/api/userinfo', headers={ 'Authorization': 'Bearer ' + self.oauth_tokengetter()[0]}).content
            userinfo =  json.loads(resp.decode('utf-8'))

            logging.debug(userinfo)
            return {
                    'username' : userinfo['email'], #
                            #'name' : userinfo['name'], #me['name']
                            #'email' : userinfo['email'], #me['email']
                            #'first_name': 'first_name', #me['given_name'],
                            #'last_name': 'last_name', #me['family_name'],
                            }
