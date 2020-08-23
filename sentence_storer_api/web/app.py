from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

# default port for mongodb is 27017
client = MongoClient("mongodb://db:27017")
db = client.SentencesDB
users = db["Users"]

def usernameExists(username):
        if users.find( {
                "Username" : username 
        } ).count() > 0:
                return True
        else:
                return False                
                
def verifyPwd(username, password):
        # rehash passowrd given
        hashed_pwd = users.find( {"Username" : username} )[0]["Password"]   
        # return true/fasle for hashed_pwd matches the stored hashed password from the database
        return bcrypt.checkpw(password.encode('utf8'), hashed_pwd) 
        
def countTokens(username):
        # return the number of tokens stored in Tokens from the database
        tokens = users.find( {"Username" : username} )[0]["Tokens"]
        return tokens                            

class Register(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                
                # verify username is not taken, else return 303 response
                if usernameExists(username):
                        retJson = {
                                        "Message": "Username exists, enter another username",
                                        "Status Code" : 303
                                }
                        return jsonify(retJson)       
                
                # verify that the passowrd is strong
                
                # convert the password into a hashed format
                hashed_pwd = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
                
                # store username and password into the database
                users.insert( {
                        "Username" : username,
                        "Password" : hashed_pwd,
                        "Sentence" : "",
                        "Tokens"   : 6
                } )
                
                # return successful 200 ok response
                retJson = {
                                "Message": "You've successfully registered to the API",
                                "Status Code" : 200
                        }
                return jsonify(retJson)               

class Store(Resource):
        def post(self):
                # get posted data
                postedData = request.get_json()             
                                
                # retrieve/read the data
                username = postedData["username"]
                password = postedData["password"]
                sentence = postedData["sentence"]
                
                # verify username does not exist, else return 303 response
                if not usernameExists(username):
                        retJson = {
                                        "Message": "Username  doesn't exist, enter another username",
                                        "Status Code" : 303
                                }
                        return jsonify(retJson)
                
                # verify that the password matches the username, else return 302 respone
                correct_pwd = verifyPwd(username, password)                
                if not correct_pwd:
                        retJson =  {
                                        "Message" : "Incorrect password for given username",
                                        "Status Code" : 302
                                }  
                        return jsonify(retJson)                                     
                
                # verify that user has enough token, else return 301 respone
                num_tokens = countTokens(username)
                if num_tokens <= 0:
                        retJson =  {
                                        "Message" : "Token limit exceeded",
                                        "Status Code" : 301
                                }  
                        return jsonify(retJson)
                
                # store the sentence and decrease stored/given num of tokens by 1
                users.update( {"Username" : username }, 
                {
                        "$set" : {
                                        "Sentence": sentence, 
                                        "Tokens"  : num_tokens - 1
                                 }
                } )
                # return successful 200 ok response
                retJson = {
                                "Message": "Sentence is saved successfully",
                                "Status Code" : 200
                        }
                return jsonify(retJson)   

class Retrieve(Resource):
        def post(self):
                # get posted data
                postedData = request.get_json()
                
                # retrieve/read the data
                username = postedData["username"]
                password = postedData["password"]
                
                # verify username does not exist, else return 303 response
                if not usernameExists(username):
                        retJson = {
                                        "Message": "Username  doesn't exist, enter another username",
                                        "Status Code" : 303
                                }
                        return jsonify(retJson)
                
                # verify that the password matches the username, else return 302 respone
                correct_pwd = verifyPwd(username, password)                
                if not correct_pwd:
                        retJson =  {
                                        "Message" : "Incorrect password for given username",
                                        "Status Code" : 302
                                }  
                        return jsonify(retJson) 
                
                # verify that user has enough token, else return 301 respone
                num_tokens = countTokens(username)
                if num_tokens <= 0:
                        retJson =  {
                                        "Message" : "Token limit exceeded",
                                        "Status Code" : 301
                                }  
                        return jsonify(retJson)  
                         
                # decrease stored/given num of tokens by 1
                users.update( {"Username" : username }, 
                {
                        "$set" : {
                                        "Tokens"  : num_tokens - 1
                                 }
                } )
                # retrieve sentence stored by user from the database
                sentence = users.find( { "Username" : username } )[0]["Sentence"]
                # return sentence with success 200 ok response
                retJson = {
                        "Sentence" : sentence,
                        "Message"  : "Retrieved sentence successfully",
                        "Status"   : 200
                }
                return jsonify(retJson)   
                                                                                
                
api.add_resource(Register, "/register")
api.add_resource(Store, "/store")
api.add_resource(Retrieve, "/retrieve")

if __name__ == "__main__" :
        app.run(host="0.0.0.0", debug = True)
        # we need the port to be 0.0.0.0 because the user will be accessing 127.0.0.1

