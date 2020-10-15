from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

# default port for mongodb is 27017
client = MongoClient("mongodb://db:27017")
db = client.bankTransactionAPI
users = db["Users"]

def usernameExists(username):
        if users.find( { "Username" : username } ).count() == 0:
                return False
        else:
                return True                
                
def verifyPwd(username, password):
        if not usernameExists(username):
                return False
        # rehash passowrd given
        hashed_pwd = users.find( {"Username" : username} )[0]["Password"]   
        # return true/fasle for hashed_pwd matches the stored hashed password from the database
        return bcrypt.checkpw(password.encode('utf8'), hashed_pwd) 
        
def amountOwned(username):
        # return the amount of money owned by user
        cash = users.find( {"Username" : username} )[0]["Own"]
        return cash  

def amountDebt(username):
        # return the amount of money in debt by user
        debt = users.find( {"Username" : username} )[0]["Debt"]
        return debt
        
def genRetJsonDict(status, msg):
        #return the status & message
        retJson = { "Status": status, "Message": msg }
        return retJson     
        
def verifyCredentials(username, password):
        # if invalid username, return 301 
        if not usernameExists(username):
                return genRetJsonDict(301, "Invalid Username"), True
                
        # if invalid username password, return 302
        correct_pwd = verifyPwd(username, password)
        if not correct_pwd:
                return genRetJsonDict(302, "Incorrect Password"), True
        
        # if credentials are correct return empty dict
        return None, False
        
def updateAcc(username, balance):
        # update Own by balance amount
        users.update( { "Username": username }, { "$set": { "Own": balance } } )  
        return  
        
def updateDebt(username, balance):
        # update Debt by balance amount   
        users.update( { "Username": username }, { "$set": { "Debt": balance } } ) 
        return    
                                                                    
class Register(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                
                # verify username is not taken, else return 303 response
                if usernameExists(username):
                        retJson = genRetJsonDict(301, "Username exists, enter another username")
                        return jsonify(retJson)       
                
                # verify that the passowrd is strong
                
                # convert the password into a hashed format
                hashed_pwd = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
                
                # store username and password into the database
                users.insert( {
                        "Username" : username,
                        "Password" : hashed_pwd,
                        "Own"      : 0,
                        "Debt"     : 0
                } )
                
                # return successful 200 ok response
                retJson = genRetJsonDict(200, "Successfully registered to the API")
                return jsonify(retJson)               

class Deposit(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                money    = postedData["amount"]
                
                # verify credentials        
                retJson, error = verifyCredentials(username, password)
                # returning 301 & 302 errors
                if error:
                        return jsonify(retJson)
                # returning 303 not enough money
                if money <= 0:
                        return jsonify(genRetJsonDict(303, "Amount entered should be greater than zero"))
                        
                cash = amountOwned(username)     
                money -= 1
                bank_cash = amountOwned("BANK")
                updateAcc("BANK", bank_cash + 1)
                updateAcc(username, cash + money)
                
                return jsonify(genRetJsonDict(200, "Successfully added amount to account"))  
        
class Transfer(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                money    = postedData["amount"]
                sender_username = postedData["sender_username"]
                
                # verify credentials        
                retJson, error = verifyCredentials(username, password)
                # returning 301 & 302 errors
                if error:
                        return jsonify(retJson)
                        
                cash_from = amountOwned(username)     
                cash_to = amountOwned(sender_username)       
                
                # returning 304 invalid amount - amount entered <= 0 or cash < money
                if cash_from < money or cash_from <= 0:
                        return jsonify(genRetJsonDict(304, "Not enough amout to be transferred"))                         
                
                # returning 301 for invalid sender username (not present)
                if not usernameExists(sender_username):
                        return jsonify(genRetJsonDict(301, "Sender username does not exist"))
                                        
                # returning 303 not enough money
                if money <= 0:
                        return jsonify(genRetJsonDict(303, "Amount entered should be greater than zero"))
                        
                
                bank_cash = amountOwned("BANK")                
                updateAcc("BANK", bank_cash + 1)
                updateAcc(sender_username, cash_to + money - 1)
                updateAcc(username, cash_from - money)
                
                return jsonify(genRetJsonDict(200, "Successfully added amount to account"))                        
        
        
class Check_Balance(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                
                # verify credentials        
                retJson, error = verifyCredentials(username, password)
                # returning 301 & 302 errors
                if error:
                        return jsonify(retJson)
                        
                # Using projection, to hide some fields ex: password, and _id etc.
                # and retrieve the rest of the fields corresponding to the same username
                retJson = users.find( {
                        "Username": username
                }, {
                        "Password": 0,
                        "_id": 0
                } )[0]
                
                retTotJson = retJson
                #retTotJson.update(genRetJsonDict(200, "Succesfully retrieved balance"))
                return jsonify(retTotJson)

class Take_Loan(Resource):
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                money    = postedData["amount"]
                
                # verify credentials        
                retJson, error = verifyCredentials(username, password)
                # returning 301 & 302 errors
                if error:
                        return jsonify(retJson)
                
                # returning 303 not enough money
                if money <= 0:
                        return jsonify(genRetJsonDict(303, "Amount entered should be greater than zero"))
                
                cash = amountOwned(username)
                debt = amountDebt(username)
                updateAcc(username, cash + money)
                updateDebt(username, debt + money)
                
                return jsonify(genRetJsonDict(200, "Successfully transeffered loan amount to account"))                        

class Pay_Loan(Resource):   
        def post(self):
                # get posted data by the user
                postedData = request.get_json()              
                
                # retrieve the data
                username = postedData["username"]
                password = postedData["password"]
                money    = postedData["amount"]
                
                # verify credentials        
                retJson, error = verifyCredentials(username, password)
                # returning 301 & 302 errors
                if error:
                        return jsonify(retJson)
                
                # returning 303 not enough money
                if money <= 0:
                        return jsonify(genRetJsonDict(303, "Amount entered should be greater than zero"))
                
                cash = amountOwned(username)
                
                # returning 304 invalid amount - amount entered <= 0 or cash < money
                if cash < money or money <= 0:
                        return jsonify(genRetJsonDict(304, "Not enough amount to pay loan"))
                
                debt = amountDebt(username)
                updateAcc(username, cash - money)
                updateDebt(username, debt - money)
                
                return jsonify(genRetJsonDict(200, "Successfully transeffered loan amount to account"))  
                                                                                                   
                
api.add_resource(Register, "/register")
api.add_resource(Deposit, "/deposit")
api.add_resource(Transfer, "/transfer")
api.add_resource(Check_Balance, "/check_bal")
api.add_resource(Take_Loan, "/take_loan")
api.add_resource(Pay_Loan, "/pay_loan")

if __name__ == "__main__" :
        app.run(host="0.0.0.0", debug = True)
        # we need the port to be 0.0.0.0 because the user will be accessing 127.0.0.1
