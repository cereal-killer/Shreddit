#!/usr/bin/env python

import os
import sys
import logging
import argparse
import json
import yaml
import praw

from datetime import datetime, timedelta
from random import shuffle, randint
from re import sub
from praw.errors import InvalidUser, InvalidUserPass, RateLimitExceeded, \
                        HTTPException, OAuthAppRequired
from praw.objects import Comment, Submission
from yaml import YAMLObject

try:
    from loremipsum import get_sentence  # This only works on Python 2
except ImportError:
    def get_sentence():
        return '''I have been Shreddited for privacy!'''
    os_wordlist = '/usr/share/dict/words'
    if os.name == 'posix' and os.path.isfile(os_wordlist):
        # Generate a random string of words from our system's dictionary
        fh = open(os_wordlist)
        words = fh.read().splitlines()
        fh.close()
        shuffle(words)

        def get_sentence():
            return ' '.join(words[:randint(50, 150)])

__TOOL__ = "shreddit"
__VERSION__ = "4.2"


class ShredditConfig(YAMLObject):
    def __init__(self, username, password, max_score, save_directory='.', verbose=False, whitelist=None,
                 whitelist_ids=None, item='comments', sort='new', hours=24, nuke_hours=4320, edit_only=False,
                 whitelist_distinguished=False, whitelist_gilded=False, trial_run=False, clear_vote=False,
                 logger=None):

        self.logger = logger if logger else logging.getLogger(__name__)

        self.username = username
        self.password = password
        self.max_score = max_score

        self.save_directory = save_directory
        self.verbose = verbose
        self.whitelist = whitelist if whitelist is not None else []
        self.whitelist_ids = whitelist_ids if whitelist_ids is not None else []
        if item not in ['comments', 'submitted', 'overview']:
            raise Exception("Your deletion '%s' section is wrong", sort)
        self.item = item

        self.sort = sort
        self.hours = hours
        self.nuke_hours = nuke_hours
        self.edit_only = edit_only
        self.whitelist_distinguished = whitelist_distinguished
        self.whitelist_gilded = whitelist_gilded
        self.trial_run = trial_run
        self.clear_vote = clear_vote

        self.show_state()

    @classmethod
    def yaml_constructor(cls, loader, node):
        return cls(**loader.construct_mapping(node))

    def show_state(self):
        self.logger.debug("Deleting messages before %s.", datetime.now() - timedelta(hours=self.hours))
        self.logger.debug("Keeping messages from subreddits %s", ', '.join(self.whitelist))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c',
        '--config',
        default='shreddit.yml',
        help="config file to use"
    )
    return parser.parse_args()


def get_things(config, praw_reddit, logger=None):
    logger = logger if logger else logging.getLogger(__name__)
    logger.debug("Deleting items: %s", config.item)
    actions = {
        'comments': praw_reddit.user.get_comments,
        'submitted': praw_reddit.user.get_submitted,
        'overview': praw_reddit.user.get_overview
    }

    action = actions[config.item]
    return action(limit=None, sort=config.sort)


def remove_things(things, config, logger=None):
    logger = logger if logger else logging.getLogger(__name__)

    edited, deleted = 0, 0

    if not os.path.exists(config.save_directory):
        os.makedirs(config.save_directory)

    for thing in things:
        logger.debug('Starting remove function on: %s', thing)
        # Seems to be in users's timezone. Unclear.
        thing_time = datetime.fromtimestamp(thing.created_utc)
        # Exclude items from being deleted unless past X hours.
        after_time = datetime.now() - timedelta(hours=config.hours)
        if thing_time > after_time:
            if thing_time + timedelta(hours=config.nuke_hours) < datetime.utcnow():
                pass
            continue
        # For edit_only we're assuming that the hours aren't altered.
        # This saves time when deleting (you don't edit already edited posts).
        if config.edit_only:
            end_time = after_time - timedelta(hours=config.hours)
            if thing_time < end_time:
                continue

        if str(thing.subreddit).lower() in config.whitelist or thing.id in config.whitelist_ids:
            continue

        if config.whitelist_distinguished and thing.distinguished:
            continue
        if config.whitelist_gilded and thing.gilded:
            continue
        if thing.score > config.max_score:
            continue

        with open("%s/%s.json" % (config.save_directory, thing.id), "w") as fh:
            json.dump(thing.json_dict, fh)

        if config.trial_run:  # Don't do anything, trial mode!
            logger.debug("Would have deleted %s: '%s'", thing.id, thing)
            continue

        if config.clear_vote:
            thing.clear_vote()

        if isinstance(thing, Submission):
            logger.info('Deleting submission: #%s %s', thing.id, thing.url.encode('utf-8'))
        elif isinstance(thing, Comment):
            replacement_text = get_sentence()
            msg = '/r/{3}/ #{0} with:\n\t"{1}" to\n\t"{2}"'.format(
                thing.id,
                sub(b'\n\r\t', ' ', thing.body[:78].encode('utf-8')),
                replacement_text[:78],
                thing.subreddit
            )
            if config.edit_only:
                logger.info('Editing (not removing) %s', msg)
            else:
                logger.info('Editing and deleting %s', msg)

            thing.edit(replacement_text)
            edited += 1
        if not config.edit_only:
            thing.delete()
            deleted += 1

    logger.info("Finished shredding!")
    logger.info("%d items were edited", edited)
    logger.info("%d items were deleted", deleted)


def shreddit(config, logger=None):
    logger = logger if logger else logging.getLogger(__name__)
    r = praw.Reddit(user_agent="{t}/{v}".format(t=__TOOL__, v=__VERSION__))
    if config.save_directory:
        r.config.store_json_result = True

    try:
        # Try to login with OAuth2
        r.refresh_access_information()
        logger.debug("Logged in with OAuth.")
    except (HTTPException, OAuthAppRequired) as e:
        logger.warning("You should migrate to OAuth2 using get_secret.py before \
                Reddit disables this login method.")
        try:
            try:
                r.login(config.username, config.password)
            except InvalidUserPass:
                r.login()  # Supply details on the command line
        except InvalidUser as e:
            raise InvalidUser("User does not exist.", e)
        except InvalidUserPass as e:
            raise InvalidUserPass("Specified an incorrect password.", e)
        except RateLimitExceeded as e:
            raise RateLimitExceeded("You're doing that too much.", e)

    logger.info("Logged in as %s", r.user)

    things = get_things(config, r, logger=logger)
    remove_things(things, config, logger=logger)


yaml.add_constructor(u'!ShredditConfig', ShredditConfig.yaml_constructor)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout)
    shreddit_logger = logging.getLogger(__TOOL__)
    shreddit_logger.setLevel(level=logging.INFO)

    args = parse_args()
    with open(args.config, 'r') as cfg_fh:
        shreddit_config = yaml.load(cfg_fh)

    if shreddit_config.verbose:
        shreddit_logger.setLevel(level=logging.DEBUG)

    shreddit(config=shreddit_config, logger=shreddit_logger)
