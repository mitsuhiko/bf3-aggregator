#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    bf3
    ~~~

    Battlefield3 aggregator script thingy.

    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import re
import urllib2
import cookielib
import html5lib
import logging
from twitter_text import TwitterText
from datetime import datetime, timedelta
from urlparse import urljoin
from flask import Flask, Markup, render_template, json, request, url_for, \
     redirect, escape, jsonify
from flaskext.sqlalchemy import SQLAlchemy
from werkzeug.urls import url_decode, url_encode, url_quote
from werkzeug.http import parse_date

# old werkzeug version
try:
    from werkzeug.http import http_date
except ImportError:
    from werkzeug import http_date

from werkzeug.contrib.atom import AtomFeed


app = Flask(__name__)
app.config.from_pyfile('defaults.cfg')
app.config.from_pyfile('local.cfg')
db = SQLAlchemy(app)
logger = logging.getLogger('bf3')
logging.basicConfig(level=logging.ERROR)


_security_token_re = re.compile(r'var SECURITYTOKEN\s+=\s+"([^"]+)"')
_post_reference_re = re.compile(
    r'<img class="inlineimg" src="images/icons/icon1\.gif" alt="" border="0" />'
    r'\s+<a href=".*?\.html#post(\d+)'
)
_post_detail_re = re.compile(
    r'(?P<date>(?:Today|Yesterday|\d{2}-\d{2}-\d{4}), \d{2}:\d{2} (?:AM|PM)).*?'
    r'<!-- message -->(?P<contents>.*?)<!-- / message -->'
    r'(?usm)'
)


@app.template_filter('datetimeformat')
def format_datetime(obj):
    return obj.strftime('%Y-%m-%d @ %H:%M')


def request_wants_json():
    """Returns true if the request wants to get JSON output"""
    # we only accept json if the quality of json is greater than the
    # quality of text/html because text/html is preferred to support
    # browsers that accept on */*
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
       request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def url_for_different_page(page):
    """References a different page."""
    args = request.view_args.copy()
    args['page'] = page
    return url_for(request.endpoint, **args)
app.jinja_env.globals['url_for_different_page'] = url_for_different_page


class Developer(db.Model):
    """Represents a developer in the database"""
    id = db.Column('developer_id', db.Integer, primary_key=True)
    twitter_name = db.Column(db.String(50))
    forum_name = db.Column(db.String(50))
    name = db.Column(db.String(50))
    slug = db.Column(db.String(50))

    _cfg_dict = None

    @staticmethod
    def get_or_create(d):
        rv = Developer.query.filter_by(name=d['realname']).first()
        if rv is not None:
            return rv
        rv = Developer()
        rv.name = d['realname']
        rv.twitter_name = d.get('twitter_name')
        rv.forum_name = d.get('forum_name')
        rv.slug = u'-'.join(rv.name.split()).lower()
        db.session.add(rv)
        return rv

    @property
    def cfg_dict(self):
        if self._cfg_dict is None:
            for d in app.config['DICE_DEVELOPERS']:
                if d['realname'] == self.name:
                    self._cfg_dict = d
                    break
        return self._cfg_dict

    @property
    def description(self):
        return Markup(self.cfg_dict.get('description', ''))

    def to_dict(self, summary=False):
        rv = {
            'twitter_name':     self.twitter_name,
            'forum_name':       self.forum_name,
            'name':             self.name
        }
        if not summary:
            rv['description'] = self.description
        return rv


class Message(db.Model):
    """Represents a single message"""
    id = db.Column('message_id', db.Integer, primary_key=True)
    developer_id = db.Column(db.Integer,
                             db.ForeignKey('developer.developer_id'))
    text = db.Column(db.String)
    source = db.Column(db.String(20))
    pub_date = db.Column(db.DateTime)
    developer = db.relation('Developer')
    reference_id = db.Column(db.String(50))

    def __init__(self, developer, text, source, pub_date, reference_id):
        assert source in ('forums', 'twitter'), 'unknown source'
        self.developer = developer
        self.text = text
        self.source = source
        self.pub_date = pub_date
        self.reference_id = reference_id

    @property
    def html_text(self):
        if self.source == 'twitter':
            return Markup(TwitterText(unicode(escape(self.text)))
                .autolink.auto_link())
        return Markup(self.text)

    @property
    def source_url(self):
        if self.source == 'forums':
            return urljoin(app.config['FORUM_URL'],
                           '/%s-post.html' % self.reference_id)
        elif self.source == 'twitter':
            return 'http://twitter.com/%s/status/%s' % (
                self.developer.twitter_name,
                self.reference_id
            )
        return '#'

    @property
    def source_prefix(self):
        if self.source == 'forums':
            return u'A forum post'
        elif self.source == 'twitter':
            return u'A tweet'
        return u'Something'

    def to_dict(self, summary=False):
        rv = {
            'source':       self.source,
            'source_url':   self.source_url,
            'date':         http_date(self.pub_date),
            'developer':    self.developer.to_dict(summary=True)
        }
        if not summary:
            rv['html_text'] = unicode(self.html_text)
            if self.source == 'twitter':
                rv['twitter_text'] = self.text
        return rv


class AuthenticationError(Exception):
    """Raised if an authentication error occurred."""


class ForumSearcher(object):
    """Gives access to the Battlefield3 forums."""
    user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'

    def __init__(self, username, password):
        self.username = username
        self.password = password

        self.jar = cookielib.CookieJar()
        self._opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.jar))

        resp = self.open_url('/login.php?do=login', data={
            'vb_login_username':        self.username,
            'vb_login_password':        self.password,
            'securitytoken':            'guest',
            'do':                       'login'
        })
        if 'Thank you for logging in' not in resp.read():
            raise AuthenticationError()

    def open_url(self, url, query=None, data=None, headers=None,
                 inject_token=False):
        url = urljoin(app.config['FORUM_URL'], url)
        if inject_token:
            assert isinstance(data, dict), 'data dictionary has to be set'
            data['securitytoken'] = self.get_security_token(url)
        if query is not None:
            if '?' in url:
                url, existing_query = url.rsplit('?', 1)
                existing_query = url_decode(existing_query)
            else:
                existing_query = {}
            existing_query.update(query)
            url += '?' + url_encode(existing_query)
        if headers is None:
            headers = {}
        if data is not None:
            data = url_encode(data)
            headers['content-type'] = 'application/x-www-form-urlencoded'
        headers.setdefault('user-agent', self.user_agent)
        req = urllib2.Request(url, data, headers)
        return self._opener.open(req)

    def get_security_token(self, url):
        """Return a security token."""
        resp = self.open_url(url)
        data = resp.read()
        match = _security_token_re.search(data)
        if match is None:
            raise RuntimeError('Could not find security token for %s' % url)
        token = match.group(1)
        logging.debug('Got security token for %s: %s', url, token)
        return token

    def find_all_posts_from_search_results(self, search_html):
        """Finds all post ids from the search result"""
        for match in _post_reference_re.finditer(search_html):
            yield int(match.group(1))

    def parse_date(self, string):
        """Parses a date from the forums."""
        args = string.strip().lower().rsplit(None, 1)
        if args[0].startswith(('today,', 'yesterday,')):
            strdelta, strtime = args[0].split(',', 1)
            time = datetime.strptime(strtime.strip(), '%H:%M')
            now = datetime.utcnow()
            val = time.replace(day=now.day, month=now.month, year=now.year)
            if strdelta == 'yesterday':
                val -= timedelta(days=1)
        else:
            val = datetime.strptime(args[0], '%d-%m-%Y, %H:%M')
        if args[-1] == 'pm':
            val += timedelta(hours=12)
        return val

    def parse_text(self, text):
        """Parses the text from a message and strips some malicous HTML
        and tries to restore simplified HTML.
        """
        def make_absolute_url(url):
            return urljoin(app.config['FORUM_URL'], url)

        def remove_leading_brs(node):
            prev = node.getprevious()
            while prev is not None:
                if prev.tag != 'br' or (prev.text and prev.text.strip()):
                    break
                node = prev
                prev = node.getprevious()
                node.getparent().remove(node)

        def move_table_contents_out(node):
            parent = node.getparent()
            contents = node.getchildren()[0].getchildren()[0].getchildren()[0]
            node.addnext(contents)
            parent.remove(node)

        def transform(node):
            if '}' in node.tag:
                node.tag = node.tag.split('}')[-1]
            if node.tag == 'a':
                node.attrib.pop('target', None)
                if 'href' in node.attrib:
                    node.attrib['href'] = make_absolute_url(node.attrib['href'])
            elif node.tag == 'script':
                return
            elif node.tag == 'img':
                if 'src' in node.attrib:
                    node.attrib['src'] = make_absolute_url(node.attrib['src'])
            elif node.tag == 'table':
                node.attrib.pop('cellpadding', None)
                node.attrib.pop('width', None)
                node.attrib.pop('border', None)
                node.attrib.pop('cellspacing', None)
            elif node.tag == 'div':
                if node.getchildren():
                    div_children = node.getchildren()
                    if len(div_children) >= 2 and \
                       div_children[0].tag.split('}')[-1] == 'div' and \
                       div_children[0].text and \
                       div_children[0].text.strip() == 'Quote:' and \
                       div_children[1] is not None and \
                       div_children[1].tag.split('}')[-1] == 'table':
                        node.tag = 'blockquote'
                        remove_leading_brs(node)
                        move_table_contents_out(div_children[1])
                        node.remove(div_children[0])

            for key in node.attrib.keys():
                if key.startswith('xmlns:') or \
                   key in ('id', 'class', 'style'):
                    del node.attrib[key]

            for child in node.getchildren():
                new_child = transform(child)
                if new_child != child:
                    if new_child is not None:
                        child.addnext(new_child)
                    node.remove(child)
            return node

        prefix, root_node = html5lib.parseFragment(text, treebuilder='lxml')
        node = transform(root_node)
        node.attrib.clear()
        node.tail = None

        walker = html5lib.treewalkers.getTreeWalker('lxml')
        stream = walker(node)
        serializer = html5lib.serializer.htmlserializer.HTMLSerializer(omit_optional_tags=True)
        output_generator = serializer.serialize(stream)
        return u''.join(output_generator)

    def get_post(self, post_id):
        """Gets all relevant information for the given post"""
        html = self.open_url('/%d-post.html' % post_id).read()
        post = _post_detail_re.search(html)
        if post is None:
            raise RuntimeError('Could not parse post :(')
        groups = post.groupdict()
        return {
            'id':           post_id,
            'date':         self.parse_date(groups['date']),
            'text':         self.parse_text(groups['contents'])
        }

    def find_user_posts(self, username, forum_id=None):
        """Finds the posts of a user in a given forum"""
        if forum_id is None:
            forum_id = app.config['FORUM_ID']
        logger.info('Looking for posts by %s in forum #%d',
                      username, forum_id)
        resp = self.open_url('/search.php', data={
            'do':               'process',
            'searchuser':       username,
            'exactname':        '1',
            'forumchoice[]':    '%d' % forum_id,
            'childforums':      '1',
            'saveprefs':        '1',
            'beforeafter':      'after',
            'sortby':           '',
            'titleonly':        '0',
            'replyless':        '0',
            'replylimit':       '0',
            'searchdate':       '0',
            'sortby':           'lastpost',
            'order':            'descending',
            'showposts':        '1',
            'tag':              ''
        }, inject_token=True)

        return self.find_all_posts_from_search_results(resp.read())


def get_forum_searcher():
    """Return a useful forum searcher."""
    return ForumSearcher(app.config['FORUM_USERNAME'],
                         app.config['FORUM_PASSWORD'])


def get_tweets(username):
    """Returns the tweets of a given user"""
    resp = urllib2.urlopen('http://twitter.com/statuses/user_timeline/' +
                           url_quote(username) + '.json')
    return json.load(resp)


def sync_forum_posts(searcher, developer):
    """Finds new forum posts for the given developer"""
    logger.info('Synching forum posts for %s', developer.name)
    for post_id in searcher.find_user_posts(developer.forum_name):
        msg = Message.query.filter_by(
            source='forums', reference_id=str(post_id)).first()
        if msg is not None:
            continue
        logger.info('Found new post #%d', post_id)
        details = searcher.get_post(post_id)
        msg = Message(developer, details['text'], 'forums',
                      details['date'], str(post_id))
        db.session.add(msg)


def sync_tweets(developer):
    """Finds new tweets for the given developer"""
    logger.info('Checking tweets of @%s', developer.twitter_name)
    tweets = get_tweets(developer.twitter_name)
    for tweet in tweets:
        if tweet.get('in_reply_to_user_id'):
            continue
        msg = Message.query.filter_by(
            source='twitter', reference_id=tweet['id_str']).first()
        if msg is not None:
            continue
        logger.info('Found new tweet #%s' % tweet['id_str'])
        msg = Message(developer, tweet['text'], 'twitter',
                      parse_date(tweet['created_at']), tweet['id_str'])
        db.session.add(msg)


def sync():
    """Synchronize with database"""
    logger.info('Synchronizing upstream posts')
    searcher = get_forum_searcher()
    for developer in app.config['DICE_DEVELOPERS']:
        dev = Developer.get_or_create(developer)
        if dev.forum_name is not None:
            sync_forum_posts(searcher, dev)
        if dev.twitter_name is not None:
            sync_tweets(dev)
    db.session.commit()


def show_listing(template, page, query, per_page=30, context=None):
    """Helper that renders listings"""
    pagination = query \
        .options(db.eagerload('developer')) \
        .order_by(Message.pub_date.desc()) \
        .paginate(page, per_page)
    if request_wants_json():
        return jsonify(messages=[x.to_dict() for x in pagination.items])

    if context is None:
        context = {}
    context['pagination'] = pagination
    return render_template(template, **context)


@app.route('/', defaults={'page': 1})
@app.route('/page/<int:page>')
def show_all(page):
    return show_listing('show_all.html', page, Message.query)


@app.route('/feed.atom', defaults={'source': 'all'})
@app.route('/<any(twitter, forums):source>/feed.atom')
@app.route('/developer/<slug>/feed.atom', defaults={'source': 'developer'})
def feed(source, slug=None):
    query = Message.query
    if source == 'developer':
        developer = Developer.query.filter_by(slug=slug).first_or_404()
        query = query.filter_by(developer=developer)
    elif source != 'all':
        query = query.filter_by(source=source)
    items = query.order_by(Message.pub_date.desc()).limit(30).all()
    feed = AtomFeed(u'BF3 Development News Aggregator',
                    subtitle=u'News by battlefield developers',
                    feed_url=request.url, url=request.url_root)
    for item in items:
        feed.add('%s by %s' % (item.source_prefix, item.developer.name),
                 unicode(item.html_text),
                 content_type='html', author=item.developer.name,
                 url=item.source_url, updated=item.pub_date)
    return feed.get_response()


@app.route('/twitter/', defaults={'page': 1})
@app.route('/twitter/page/<int:page>')
def show_tweets(page):
    return show_listing('show_twitter.html', page, \
        Message.query.filter_by(source='twitter'))


@app.route('/forums/', defaults={'page': 1})
@app.route('/forums/page/<int:page>')
def show_forums(page):
    return show_listing('show_forums.html', page, \
        Message.query.filter_by(source='forums'), per_page=10)


@app.route('/developer/<slug>/', defaults={'page': 1})
@app.route('/developer/<slug>/page/<int:page>')
def show_developer(slug, page):
    developer = Developer.query.filter_by(slug=slug).first_or_404()
    return show_listing('show_developer.html', page, \
        Message.query.filter_by(developer=developer),
        context={'developer': developer})


@app.route('/developer/')
def show_developers_redirect():
    return redirect(url_for('show_developers'))


@app.route('/developers/')
def show_developers():
    return render_template('developers.html',
        developers=Developer.query.order_by(Developer.name).all())


@app.route('/about')
def about():
    return render_template('about.html')
