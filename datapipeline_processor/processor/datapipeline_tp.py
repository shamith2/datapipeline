# Copyright 2022 Shamith Achanta
#
# References: https://github.com/askmish/sawtooth-simplewallet
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

'''
Transaction Family class for Client classes

'''

import traceback
import sys
import hashlib
import logging

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

LOGGER = logging.getLogger(__name__)

# Transaction Family Name
FAMILY_NAME = "datapipeline"

def _hash(data):
    '''Compute the SHA-512 hash and return the result as hex characters.'''
    return hashlib.sha512(data).hexdigest()

# Prefix for simplewallet is the first six hex digits of SHA-512(TF name).
sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]

class ClientTransactionHandler(TransactionHandler):
    '''                                                       
    Transaction Processor class for the Data Pipeline Transaction Family                                
    This with the validator using the accept, get/set functions

    '''

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ["1.0"]

    @property
    def namespaces(self):
        return [self._namespace_prefix]

    def apply(self, transaction, context, client_type):
        '''
        This implements the apply function for this transaction handler
                                                              
        This function does most of the work for this class by processing,
        a single transaction for the Data Pipeline Transaction Family

        '''                                                   
        
        # Get the payload and extract class-specific information
        header = transaction.header
        payload_list = transaction.payload.decode().split(",")
        operation = payload_list[0]
        
        if client_type == "wallet":
            amount = payload_list[1]
        else:
            json_file = str(payload_list[1])

        # Get the public key sent from the client.
        from_key = header.signer_public_key

        # Perform the operation.
        LOGGER.info("Operation = " + operation)

        if operation == "deposit":
            self._make_deposit(context, amount, from_key)
        
        elif operation == "store":
            self._store_data(context, str(json_file), from_key)
        
        elif operation == "withdraw":
            self._make_withdraw(context, amount, from_key)
        
        elif operation == "remove":
            self._remove_data(context, str(json_file), from_key)
        
        elif operation == "transfer":
            if len(payload_list) == 3:
                to_key = payload_list[2]
            
            self._make_transfer(context, amount, to_key, from_key)
        
        elif operation == "data_transfer":
            if len(payload_list) == 3:
                to_key = payload_list[2]
            
            self._data_transfer(context, str(json_file), to_key, from_key)
        
        else:
            LOGGER.info("Unhandled action ")

    def _make_deposit(self, context, amount, from_key):
        wallet_address = self._get_client_address(from_key)
        LOGGER.info("Got the key {} and the wallet address {} ".format(from_key, wallet_address))
        current_entry = context.get_state(list(wallet_address))
        new_balance = 0

        if current_entry == []:
            LOGGER.info("No previous deposits, creating new deposit {} ".format(from_key))
            new_balance = int(amount)
        else:
            balance = int(current_entry[0].data)
            new_balance = int(amount) + int(balance)

        state_data = str(new_balance).encode('utf-8')
        addresses = context.set_state({wallet_address: state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
    
    def _store_data(self, context, json_file, from_key):
        client_address = self._get_client_address(from_key)
        LOGGER.info("Got the key {} and the wallet address {} ".format(from_key, client_address))
        current_entry = context.get_state(list(client_address))

        LOGGER.info("Adding Data File: {} ".format(json_file))

        current_entry += (json_file.encode('utf-8'),)
        addresses = context.set_state({client_address: current_entry})

        if len(addresses) < 1:
            raise InternalError("State Error")

    def _make_withdraw(self, context, amount, from_key):
        wallet_address = self._get_client_address(from_key)
        LOGGER.info("Got the key {} and the wallet address {} ".format(from_key, wallet_address))
        current_entry = context.get_state([wallet_address])
        new_balance = 0

        if current_entry == []:
            LOGGER.info('No user with the key {} '.format(from_key))
        
        else:
            balance = int(current_entry[0].data)
            
            if balance < int(amount):
                raise InvalidTransaction("Not enough money. The amount ' + 'should be lesser or equal to {} ".format(balance))
            else:
                new_balance = balance - int(amount)

        LOGGER.info('Withdrawing {} '.format(amount))
        state_data = str(new_balance).encode('utf-8')
        addresses = context.set_state({self._get_client_address(from_key): state_data})

        if len(addresses) < 1:
            raise InternalError("State Error")
    
    def _remove_data(self, context, json_file, from_key):
        client_address = self._get_client_address(from_key)
        LOGGER.info("Got the key {} and the wallet address {} ".format(from_key, client_address))
        current_entry = list(context.get_state(list(client_address)))

        if current_entry == []:
            LOGGER.info("No data entry with the key {} ".format(from_key))

        LOGGER.info("Removing {} ".format(json_file))
        current_entry = tuple(current_entry.remove(json_file))
        addresses = context.set_state({self._get_client_address(from_key): current_entry})

        if len(addresses) < 1:
            raise InternalError("State Error")

    def _make_transfer(self, context, transfer_amount, to_key, from_key):
        transfer_amount = int(transfer_amount)
        if transfer_amount <= 0:
            raise InvalidTransaction("The amount cannot be <= 0")

        wallet_address = self._get_client_address(from_key)
        wallet_to_address = self._get_client_address(to_key)
        
        LOGGER.info("Got the from key {} and the from wallet address {} ".format(
            from_key, wallet_address))
        
        LOGGER.info("Got the to key {} and the to wallet address {} ".format(
            to_key, wallet_to_address))
        
        current_entry = context.get_state(list(wallet_address))
        current_entry_to = context.get_state(list(wallet_to_address))

        if current_entry == []:
            LOGGER.info("No user (debtor) with the key {} ".format(from_key))
        if current_entry_to == []:
            LOGGER.info("No user (creditor) with the key {} ".format(to_key))

        balance = int(current_entry[0].data)
        balance_to = int(current_entry_to[0].data)
        if balance < transfer_amount:
            raise InvalidTransaction("Not enough money. " +
                "The amount should be less or equal to {} ".format(balance))
        else:
            LOGGER.info("Debiting balance with {} ".format(transfer_amount))
            update_debtor_balance = balance - int(transfer_amount)
            state_data = str(update_debtor_balance).encode('utf-8')
            context.set_state({wallet_address: state_data})
            update_beneficiary_balance = balance_to + int(transfer_amount)
            state_data = str(update_beneficiary_balance).encode('utf-8')
            context.set_state({wallet_to_address: state_data})

    def _data_transfer(self, context, json_file, to_key, from_key):
        if json_file == "":
            raise InvalidTransaction("File cannot be Empty")

        client_address = self._get_client_address(from_key)
        client_to_address = self._get_client_address(to_key)
        
        LOGGER.info("Got the from key {} and the from client address {} ".format(
            from_key, client_address))
        
        LOGGER.info("Got the to key {} and the to client address {} ".format(
            to_key, client_to_address))
        
        current_entry = list(context.get_state(list(client_address)))
        current_entry_to = context.get_state(list(client_to_address))

        if current_entry == []:
            LOGGER.info("No client with the key {} ".format(from_key))
        if current_entry_to == []:
            LOGGER.info("No client with the key {} ".format(to_key))

        LOGGER.info("Initiating Data Transfer: {} ".format(json_file))

        current_entry_to += (json_file.encode('utf-8'),)
        current_entry = tuple(current_entry.remove(json_file))
        
        context.set_state({client_address: current_entry})
        context.set_state({client_to_address: current_entry_to})

    def _get_client_address(self, from_key):
        return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + _hash(from_key.encode('utf-8'))[0:64]

def setup_loggers():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

def main():
    '''
    Entry-point function for the client transaction processor
    
    '''
    
    setup_loggers()
    
    try:
        # Register the transaction handler and start it.
        processor = TransactionProcessor(url='tcp://validator:4004')

        handler = ClientTransactionHandler(sw_namespace)

        processor.add_handler(handler)

        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
