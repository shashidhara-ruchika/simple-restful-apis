from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

# default port for mongodb is 27017
client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]

def usernameExists(username):
        if users.find( {
                "Username" : username 
        } ).count() == 0:
                return False
        else:
                return True                
                
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
                        "Tokens"   : 6
                } )
                
                # return successful 200 ok response
                retJson = {
                                "Message": "You've successfully registered to the API",
                                "Status Code" : 200
                        }
                return jsonify(retJson)               

class Detect_Sim(Resource):
        def post(self):
                # get posted data
                postedData = request.get_json()             
                                
                # retrieve/read the data
                username = postedData["username"]
                password = postedData["password"]
                text1 = postedData["text1"]
                text2 = postedData["text2"]
                
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
                
                # calculating the edit distance                
                nlp = spacy.load("en_core_web_sm")
                # converting string to nlp model processor
                text1 = nlp(text1)
                text2 = nlp(text2)
                # find ratio of similarity btw 0(least similar) & 1(most similar)
                ratio = text1.similarity(text2)  
                # store the similarity ratio and decrease the number of tokens by 1
                retJson = {
                                "Message": "Similarity Score calculated successfully",
                                "Status Code" : 200, 
                                "Similarity" : ratio
                        }       
                #num_tokens = countTokens(username)   
                users.update( { "Username" : username, } , 
                              { "$set" : { "Tokens" : num_tokens - 1} } )
                # return retJson with 200 successful response  
                return jsonify(retJson)   

class Refill(Resource):
        def post(self):
                # get posted data
                postedData = request.get_json()
                
                # retrieve/read the data
                username = postedData["username"]
                admin_password = postedData["admin_pw"]
                refill_amount = postedData["refill"]
                
                # verify username does not exist, else return 303 response
                if not usernameExists(username):
                        retJson = {
                                        "Message": "Username  doesn't exist, enter another username",
                                        "Status Code" : 303
                                }
                        return jsonify(retJson)
                
                # verify that the admin password matches the username, else return 302 respone
                # change to verifying for hashed version strored in db
                #correct_pwd = verifyPwd(username, admin_password)    
                correct_pwd = "abc123"            
                if not correct_pwd == admin_password:
                        retJson =  {
                                        "Message" : "Incorrect Admin Password",
                                        "Status Code" : 304
                                }  
                        return jsonify(retJson) 
                
                # refill the num of tokens by refill_amount
                num_tokens = countTokens(username)    
                new_tokens = refill_amount + num_tokens                     
                # update the num of tokens with new_tokens
                users.update( {"Username" : username }, 
                {
                        "$set" : {
                                        "Tokens"  : new_tokens
                                 }
                } )
                # return sentence with success 200 ok response
                retJson = {
                        "Message"  : "Refilled Tokens Successfully",
                        "Status"   : 200,
                        "New Number of Tokens" : new_tokens
                }
                return jsonify(retJson)   
                                                                                
                
api.add_resource(Register, "/register")
api.add_resource(Detect_Sim, "/detect_sim")
api.add_resource(Refill, "/refill")

if __name__ == "__main__" :
        app.run(host="0.0.0.0", debug = True)
        # we need the port to be 0.0.0.0 because the user will be accessing 127.0.0.1

