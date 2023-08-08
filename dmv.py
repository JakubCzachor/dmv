from cryptography.fernet import Fernet
import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from flask import Flask, jsonify, request
import requests

class BlockChain(object):
    _vin = ""  # Used to keep track of inventory
    _buyerSeller = ""  # 0 if buyer, #1 if seller, #2 if dmv
    _id = ""  # id of node
    _money = int()  # money
    _key = ""  # key
    recievedEncrypted = False  # default vals
    acknowledgeKeyRec = False  # default vals
    acknowledgeMoney2 = False  # default vals

    def __init__(self):
        self.chain = []
        self.current_transactions = []

        self.new_block(previous_hash=1, proof=100)  # Genesis block
        self.nodes = set()


    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
        :return: None
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    # getter for buyerseller role
    def getBuyerSeller(self):
        return self._buyerSeller

    # getter for VIN, checks if node is in possession of vehicle
    def getVIN(self):
        return self._vin

    # getter for ID
    def getID(self):
        return self._id

    # setter for ID
    def setID(self, id):
        self._id = id

    # setter for VIN, will be used to add VIN to node
    def setVIN(self, vin):
        self._vin = vin

    def getMoney(self):
        return self._money

    # setter for BuyerSeller Role
    def setBuyerSeller(self, buyerSeller):
        self._buyerSeller = buyerSeller

    def acknowledgeEncrypted(self):
        if (self.getBuyerSeller() == "0"):  # checks if Node is Buyer
            recievedEncrypted = True

    def acknowledgeKey(self, buyerNode):
        if (self.getBuyerSeller() == "2"):  # Checks if Node is DMV
            if (self._key != ""):
                self.acknowledgeKeyRec = True
            else:
                return("Error")

    def acknowledgeMoney(self, amount):
        if (self.getBuyerSeller() == "2"):  # Checks if Node is DMV
            if (self._money == amount):
                self.acknowledgeMoney2 = True
        else:
            return("Error - Money")

    def sendKey(self, dmvNode): #Sends key to the DMV
        dmvNode._key = self._key

    def sendEncrypted(self, buyerNode, dmvNode, title):  # sends encrypted key to the dmv
        if (self.getBuyerSeller() == "1" and buyerNode.getBuyerSeller() == "0" and dmvNode.getBuyerSeller() == "2"):
            if (self.getVIN() == title):
                encryptedTitle, key = encryptKey(title)
            else:
                print("Somethings messed up Encrypted")
            buyerNode.setVIN(encryptedTitle)
            dmvNode._key = key
            self._key = key
            dmvNode.acknowledgeKey(buyerNode)

        else:
            print("Error")

    def printKey(self):
        return self._key

    def sendMoney(self, dmvNode, amount): #Sends money to DMV
        money1 = int(self._money)
        if(money1>=amount): #Validates that the node has enough money
            self._money = int(self._money) - int(amount) #Subtracts money
            dmvNode._money = amount #Gives the dmv the money
            dmvNode.acknowledgeMoney = True#DMV announces they have recieved the money

    def sendMoneyToSeller(self, sellerNode, amount):
        if(self.getBuyerSeller() == "2"):
            sellerNode._money += amount
            self._money -= amount
            sellerNode._key = "" #resets title
            sellerNode._vin = "" #resets vin
        else:
            print("somethings wrong")

    def checkMoney(self, dmvNode):
        if(dmvNode.getBuyerSeller() == 2): #Checks if correct role
            if(dmvNode.recievedMoney == True): #Checks if DMV recieved money
                self.acknowledgeMoney == True #Seller node acknowledges the money
            else:
                print("Hasnt recieved money yet") #DMV hasnt recieved money yet
                return -1
        else:
            print("Wrong role") #DMV role has the wrong role
            return -1

    def sendKeyToBuyer(self, buyerNode):
        if(self.acknowledgeMoney == True): #Verifies that money has been recieved by the DMV
            buyerNode._key = self._key #Buyer is now in possession of the key
        else:
            print("DMV hasnt recieved money yet")
            return -1
    def setMoney(self, amount):
        self._money = str(amount)


    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    @staticmethod
    def hash(block):
        # Hashes a Block
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof, buyerNode, dmvNode):

        if (buyerNode.acknowledgeEncrypted() == True and dmvNode.recievedMoney == True):

            proof = 0
            while self.valid_proof(last_proof, proof) is False:
                proof += 1

            return proof
        else:
            print("Somethings wrong")
            return -1

    @staticmethod
    def valid_proof(last_proof, proof):

        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    @property
    def last_block(self):
        return self.chain[-1]

    def new_transaction(self, buyerNode, sellerNode, dmvNode, amount, title):

        if (buyerNode.getBuyerSeller() == "0" and sellerNode.getBuyerSeller() == "1"):
            if (sellerNode.getVIN() == title):  # checks if sellerNode has VIN
                if (int(buyerNode.getMoney()) >= int(amount)):
                    self.current_transactions.append({
                        'sender': buyerNode,
                        'recipient': sellerNode,
                        'amount': amount,
                        'title' : title
                    })
                else:
                    print("wrong amount of money")
                    return -1
            else:
                print("wrong title")
                return -1
        elif (buyerNode.getBuyerSeller != "0" or sellerNode.getBuyerSeller() != "1"):
            print("wrong")
            return -1
        elif (dmvNode.getBuyerSeller() != "2"):
            print("wrong2")
            return -1

        return self.last_block['index'] + 1
def encryptKey(title):
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(title.encode())

    # TESTING#
    # print("Encrypted Title: ", token)
    # print("Key: ", key)

    return token, key


def decryptKey(encryptedTitle, key):
    f = Fernet(key)
    title = f.decrypt(encryptedTitle)
    title = title.decode()

    # TESTING#
    # print("Encrypted Title: ", encryptedTitle)
    # print("Key: ", key)
    # print("Unencrypted Title: ",title)

    return title
encryptTitle, key = encryptKey("28328818")
title = decryptKey(encryptTitle, key)

buyerNode = BlockChain()
buyerNode.setBuyerSeller("0")
buyerNode.setID("buyer")
buyerNode.setMoney(50000)
app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

blockchain = BlockChain()
@app.route('/get-id', methods = ['POST'])
def getidfunc():
    request_data = request.get_json(force=True)
    node = request_data['nodes']
    hi = node.getID()
    print(hi)
    return hi
@app.route('/get-nodes', methods = ['GET'])
def getNodes():
    print(list(blockchain.nodes))
    return "200"
@app.route('/get-test', methods= ['POST'])
def getData():
    request_data = request.get_json(force=True)
    nodes = request_data['nodes']
    value = request_data['value']
    print(nodes, value)
    return "200"

@app.route('/setbuyer', methods=['POST'])
def setbuyer():
    request_data = request.get_json(force=True)
    nodes = request_data['nodes']
    role = request_data['role']
    #print(values('nodes'))
    #print(values['role'])
    print(nodes, role)
    blockchain[nodes].setBuyerSeller(role)
    response = {'message': f'Role for {nodes} has been set to {nodes.getBuyerSeller()}'}
    return jsonify(response), 201

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json(force=True)

    nodes = values['nodes']
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
@app.route('/sendEncrypted', methods=['POST'])
def sendEncryptedTitle():
    #def sendEncrypted(self, buyerNode, dmvNode, title):  # sends encrypted key to the dmv
    values = request.get_json()
    required = ['sellernode''buyernode', 'dmvnode' 'title']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['sellernode'].sendEncrypted(values('buyernode'), values('dmvnode'), values('title'))

    response = {'message': f'Encrypted Title has been sent to {values("buyernode")}, key has been sent to {values("dmvnode")}'}
    return jsonify(response), 201


@app.route('/sendMoney', methods=['POST'])
def sendMoneyToDMV():

    values = request.get_json()
    required = ['buyernode', 'dmvNode', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['sellernode'].sendMoney(values('dmvnode'), values('amount'))
    response = {
        'message': f'Money has been sent to the DMV {values("dmvnode")} for {values("amount")}'}
    return jsonify(response), 201

@app.route('/checkMoney', methods=['POST'])
def checkIfMoneySent():
    values = request.get_json()
    required = ['dmvNode', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['dmvNode'].checkIfMoneySent(values('dmvNode'), values('amount'))
    response = {
        'message': f'Money has been sent to the DMV {values("dmvnode")} for {values("amount")}'}
    return jsonify(response), 201


@app.route('/setMoney', methods=['POST'])
def setMoneyBuyer():
    values = request.get_json(force=True)
    required = ['buyernode', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['buyernode'].setMoney(values('amount'))
    response = {
        'message': f'{values("buyernode")} Now has {values("buyernode").getMoney()}'}
    return jsonify(response), 201

@app.route('/sendMoneySeller', methods=['POST'])
def sendMoneySeller():
    values = request.get_json(force=True)
    required = ['sellernode', 'dmvnode','amount']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['buyernode'].setMoney(values('amount'))
    response = {
        'message': f'{values("buyernode")} Now has {values("buyernode").getMoney()}'}
    return jsonify(response), 201

@app.route('/setTitle', methods=['POST'])
def setTitleSeller():
    values = request.get_json(force=True)
    required = ['sellernode', 'title']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['sellernode'].setVIN(values('title'))
    response = {
        'message': f'{values("sellernode")} Now has {values("sellernode").getVIN()}'}
    return jsonify(response), 201
@app.route('/sendKeyBuyer', methods=['POST'])
def sendBuyerKey():
    values = request.get_json(force=True)
    required = ['dmvnode','buyernode']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['dmvnode'].sendKeyToBuyer(values('buyernode'))
    response = {
        'message': f'{values("buyernode")} Now has {values("buyernode").printKey()}'}
    return jsonify(response), 201

@app.route('/sendMoneySeller', methods=['POST'])
def sendSellerMoney():
    values = request.get_json(force=True)
    required = ['dmvnode','sellernode']
    if not all(k in values for k in required):
        return 'Missing values', 400
    values['dmvnode'].sendMoneyToSeller(values('sellernode'))
    response = {
        'message': f'{values("sellernode")} Now has {values("sellernode").getMoney()}'}
    return jsonify(response), 201



encryptTitle, key = encryptKey("28328818")
title = decryptKey(encryptTitle, key)

buyerNode = BlockChain()
buyerNode.setBuyerSeller("0")
buyerNode.setID("buyer")
buyerNode.setMoney(50000)

print("BuyerNode: ",buyerNode.getBuyerSeller())
print("Buyer Node: ", buyerNode.getMoney())

sellerNode = BlockChain()
sellerNode.setBuyerSeller("1")
sellerNode.setID("seller")
sellerNode.setVIN("123456789")

print("Seller Node: ",sellerNode.getBuyerSeller())
print("Seller ID: ",sellerNode.getID())
print("Seller VIN: ",sellerNode.getVIN())

DMVNode = BlockChain()
DMVNode.setBuyerSeller("2")
DMVNode.setID("dmv")
print("DMV Node: ",DMVNode.getBuyerSeller())

sellerNode.sendEncrypted(buyerNode, dmvNode=DMVNode, title="123456789")
print("DMV Has Recieved Key: ", DMVNode.acknowledgeKeyRec)
print("Sellers Key: ", sellerNode.printKey())
print("DMV's key: ", DMVNode.printKey())
print("Buyer Now Recieved Encrypted Title: ", buyerNode.getVIN())

buyerNode.sendMoney(dmvNode=DMVNode,amount=1000)
print("DMV now has recieved the money: ", DMVNode.acknowledgeMoney)
print("DMV now has: ", DMVNode.getMoney(), "and key: ", DMVNode.printKey())
print("Buyer now has: ", buyerNode.getMoney())

DMVNode.sendKeyToBuyer(buyerNode=buyerNode)
print("DMV can now send the key to the buyer: ", buyerNode)
print("Buyer now has both title: ", buyerNode.getVIN(), "and key: ", buyerNode.printKey())
print("DMV Now has: ", DMVNode.getMoney())

DMVNode.sendMoneyToSeller(sellerNode=sellerNode, amount=1000)
print("Seller Now Has: ", sellerNode.getMoney())
print("DMV Now has: ", DMVNode.getMoney())

buyerNode.setVIN(decryptKey(buyerNode.getVIN(),buyerNode.printKey()))
print("Buyers decreypted title: ", buyerNode.getVIN())


