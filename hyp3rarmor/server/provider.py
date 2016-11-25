import json
import logging
import time
import threading
from collections import deque
from hyp3rarmor.common.constants import *
from hyp3rarmor.common.config import config 
from hyp3rarmor.common.generate import * 

logger = logging.getLogger('provider')

class TokenClock(threading.Thread):

    def init(self, token_state, exporter):
        self.exporter = exporter
        self.token_state = token_state

    def run(self):
        while True:
            start_time = time.time()
            self.tick(start_time)
            time_left = time_till_dealth(config.token_ttl) 
            time.sleep(time_left)

    def tick(self, start_time):
        token = None
        if config.defense == DEFENSE_DN:
            #FIXME This captcha is trivial to break
            solution = self.generate_random_word(6, seed=seed) 
            token = UniversalDNBotToken(config.token_ttl, solution)
        else:
            token = UniversalIPBotToken(config.token_ttl) #generate_universal_token(config.token_size)

        self.token_state.add(token)
        if self.exporter:
            self.exporter.export(token)


class TokenState:
    """
    Because the AT is shared among all clients we keep state of the AT when it is 
    generated for fast verification
    """
    def __init__(self):
        self.window = deque(config.window_size * [{}], config.window_size)
        self.token = None
    

    def add(self, token):
        """ Add a new token 
        Args: 
            token: The authtentication token (AT)
        """
        self.window.appendleft(token)
        self.token = token


class FileExporter:
    def __init__(self):
        self.output = os.path.join(HYP3RARMOR_GEN_DIR, "token.js")

    def export(self, token):

        """Export the token to the filesystem
        Args: 
            AT: The AT to be exported
            expire: The time when the token wiill expire
        """
        json_string = None
        if config.defense == DEFENSE_DN:
            challenge_file = os.path.join(HYP3RARMOR_GEN_DIR, "challenge.png")
            generate_challange(token.challenge_solution, file=challenge_file)

        with open(self.output, "w") as f:
            f.write(token.to_json())

