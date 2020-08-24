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
