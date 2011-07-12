#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    bf3
    ~~~

    Battlefield3 aggregator script thingy.  Uses logging from the stdlib and
    something has to configure the logger before this can safely be used.

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
from functools import update_wrapper
from flask import Flask, Markup, render_template, json, request, url_for, \
     redirect, jsonify, g, session, flash, abort
from flaskext.sqlalchemy import SQLAlchemy
from flaskext.openid import OpenID
from werkzeug.urls import url_decode, url_encode, url_quote
from werkzeug.http import parse_date, http_date
from werkzeug.utils import cached_property

from werkzeug.contrib.atom import AtomFeed


app = Flask(__name__)
app.config.from_pyfile('defaults.cfg')
app.config.from_pyfile('local.cfg')
db = SQLAlchemy(app)
oid = OpenID(app)


# set up the logging system based on debug settings
if app.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    from logging.handlers import SMTPHandler
    mail_handler = SMTPHandler(app.config['MAIL_SERVER'],
                               app.config['ERROR_MAIL_SENDER'],
                               app.config['ADMINS'],
                               app.config['ERROR_MAIL_SUBJECT'])
    mail_handler.setFormatter(logging.Formatter('''\
Message type:       %(levelname)s
Location:           %(pathname)s:%(lineno)d
Module:             %(module)s
Function:           %(funcName)s
Time:               %(asctime)s

Message:

%(message)s
'''))
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.ERROR)
    root_logger.addHandler(mail_handler)


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
_steam_id_re = re.compile('steamcommunity.com/openid/id/(.*?)$')
logger = logging.getLogger('bf3')


def call_steam_api(_method, **options):
    """Calls a steam API method and returns the value"""
    options['key'] = app.config['STEAM_API_KEY']
    url = 'http://api.steampowered.com/%s/v0001/?%s' % \
        (_method.replace('.', '/'), url_encode(options))
    return json.load(urllib2.urlopen(url))


def to_base36(value):
    """Returns a base36 version of an integer"""
    buf = []
    while value:
        value, i = divmod(value, 36)
        buf.append(u'0123456789abcdefghijklmnopqrstuvwxyz'[i])
    return u''.join(reversed(buf)) or u'0'


def from_base36(value, default=None):
    """Reversal of to_base36 that only accepts lowercase"""
    if not value.islower():
        return default
    try:
        return int(value, 36)
    except (ValueError, TypeError):
        return default


class Developer(db.Model):
    """Represents a developer in the database"""
    id = db.Column('developer_id', db.Integer, primary_key=True)
    twitter_name = db.Column(db.String(50))
    forum_name = db.Column(db.String(50))
    name = db.Column(db.String(50))
    slug = db.Column(db.String(50))
    description = db.Column(db.Text)

    def __init__(self, name, twitter_name=None, forum_name=None):
        self.name = name
        self.twitter_name = twitter_name
        self.forum_name = forum_name
        self.description = u''
        self.slug = u'-'.join(self.name.lower().split())

    @property
    def description_html(self):
        return Markup(self.description)

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
    hidden = db.Column(db.Boolean)

    def __init__(self, developer, text, source, pub_date, reference_id,
                 hidden=False):
        assert source in ('forums', 'twitter'), 'unknown source'
        self.developer = developer
        self.text = text
        self.source = source
        self.pub_date = pub_date
        self.reference_id = reference_id
        self.hidden = hidden

    @property
    def html_text(self):
        if self.source == 'twitter':
            # careful: TwitterText.autolink.auto_link does *not* escape
            # HTML.  On the other hand, the twitter API will give you
            # the text HTML escaped.  Why, please ask the respective
            # authors.  It's dumb ...
            return Markup(TwitterText(self.text).autolink.auto_link())
        return Markup(self.text)

    @property
    def source_url(self):
        if self.source == 'forums':
            return urljoin(app.config['FORUM_URL'],
                           '/showthread.php?p=%s' % self.reference_id)
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


user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.user_id')),
    db.Column('message_id', db.Integer, db.ForeignKey('message.message_id'))
)


class User(db.Model):
    """Represents a user on the website.  A user can sign in with his steam
    ID and for as long as he is logged in a few extra functions unlock (such
    as favoring tweets and posts and to vote on them.
    """
    id = db.Column('user_id', db.Integer, primary_key=True)
    steam_id = db.Column(db.String(80))
    is_admin = db.Column(db.Boolean)
    favorites = db.dynamic_loader('Message', secondary=user_favorites,
                                  query_class=Message.query_class)
    nickname = db.Column(db.String(120))

    @staticmethod
    def get_or_create(steam_id, sync_nickname=True):
        user = User.query.filter_by(steam_id=steam_id).first()
        if user is None:
            user = User()
            user.steam_id = steam_id
            user.is_admin = False
            db.session.add(user)
        if sync_nickname:
            user.nickname = user.steam_data.get('personaname')
        return user

    @cached_property
    def steam_data(self):
        rv = call_steam_api('ISteamUser.GetPlayerSummaries',
                            steamids=self.steam_id)
        return rv['response']['players']['player'][0] or {}

    @property
    def slug(self):
        return to_base36(int(self.steam_id))

    @property
    def profile_url(self):
        return 'http://steamcommunity.com/profiles/%s' % self.steam_id

    @property
    def avatar_url(self):
        return self.steam_data.get('avatar')

    def login(self):
        session['user_id'] = self.id
        session.permanent = True

    def logout(self):
        if session.get('user_id') != self.id:
            return
        session.pop('user_id', None)
        session.permanent = False

    def get_favorite_status_for(self, messages):
        if not messages:
            return set()
        uf = user_favorites.c
        result = db.session.execute(user_favorites.select(
            (uf.user_id == self.id) &
            (uf.message_id.in_([msg.id for msg in messages]))
        ))
        return set(row.message_id for row in result.fetchall())

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)


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
                if prev.tag != 'br' or (prev.text and prev.text.strip()) or \
                   (prev.tail and prev.tail.strip()):
                    break
                node = prev
                prev = node.getprevious()
                node.getparent().remove(node)

        def move_table_contents_out(node):
            parent = node.getparent()
            contents = node.getchildren()[0].getchildren()[0].getchildren()[0]
            if contents.tag.split('}')[-1] == 'td':
                contents.tag = 'div'
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
                node.attrib.pop('border', None)
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


def get_forum_searcher():
    """Return a useful forum searcher."""
    return ForumSearcher(app.config['FORUM_USERNAME'],
                         app.config['FORUM_PASSWORD'])


def get_tweets(username):
    """Returns the tweets of a given user"""
    resp = urllib2.urlopen('http://twitter.com/statuses/user_timeline/' +
                           url_quote(username) + '.json')
    return json.load(resp)


def require_login(f):
    def login_protected(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return update_wrapper(login_protected, f)


def require_admin(f):
    def page_protected(*args, **kwargs):
        if not g.user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return require_login(update_wrapper(page_protected, f))


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
        hidden = bool(tweet.get('in_reply_to_user_id'))
        msg = Message.query.filter_by(
            source='twitter', reference_id=tweet['id_str']).first()
        if msg is not None:
            continue
        logger.info('Found new tweet #%s' % tweet['id_str'])
        msg = Message(developer, tweet['text'], 'twitter',
                      parse_date(tweet['created_at']), tweet['id_str'],
                      hidden)
        db.session.add(msg)


def sync():
    """Synchronize with database"""
    logger.info('Synchronizing upstream posts')
    try:
        searcher = get_forum_searcher()
    except (IOError, AuthenticationError):
        searcher = None
    for dev in Developer.query.all():
        if dev.forum_name is not None:
            if searcher is not None:
                sync_forum_posts(searcher, dev)
        if dev.twitter_name is not None:
            sync_tweets(dev)
    db.session.commit()


def show_listing(template, page, query, per_page=30, context=None,
                 show_hidden=False):
    """Helper that renders listings"""
    query = query \
        .options(db.eagerload('developer')) \
        .order_by(Message.pub_date.desc())
    if not show_hidden:
        query = query.filter_by(hidden=False)
    pagination = query.paginate(page, per_page)
    if request_wants_json():
        return jsonify(messages=[x.to_dict() for x in pagination.items])

    if context is None:
        context = {}

    # if a user is logged in and we don't want JSON output we also have
    # to fetch the information about which entries are starred
    if g.user is not None:
        context['starred'] = g.user.get_favorite_status_for(pagination.items)

    context['pagination'] = pagination
    return render_template(template, **context)


@app.before_request
def before_request():
    if app.config['MAINTENANCE'] and request.endpoint != 'static':
        return render_template('maintenance.html'), 503
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.url_defaults
def prefer_twitter_without_replies(endpoint, values):
    if endpoint == 'show_tweets':
        values.setdefault('with_replies', False)


@app.route('/', defaults={'page': 1})
@app.route('/page/<int:page>')
def show_all(page):
    return show_listing('show_all.html', page, Message.query)


@app.route('/feed.atom', defaults={'source': 'all'})
@app.route('/<any(twitter, forums):source>/feed.atom')
@app.route('/developer/<slug>/feed.atom', defaults={'source': 'developer'})
@app.route('/favs/<slug>/feed.atom', defaults={'source': 'fav'})
def feed(source, slug=None):
    query = Message.query.filter_by(hidden=False)
    if source == 'developer':
        developer = Developer.query.filter_by(slug=slug).first_or_404()
        query = query.filter_by(developer=developer)
    elif source == 'fav':
        id = from_base36(slug)
        if id is None:
            abort(404)
        user = User.query.filter_by(steam_id=unicode(id)).first_or_404()
        query = user.favorites
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


@app.route('/twitter/', defaults={'page': 1, 'with_replies': False})
@app.route('/twitter/page/<int:page>', defaults={'with_replies': False})
@app.route('/twitter/with-replies/',
           defaults={'page': 1, 'with_replies': True})
@app.route('/twitter/with-replies/page/<int:page>',
           defaults={'with_replies': True})
def show_tweets(page, with_replies):
    return show_listing('show_twitter.html', page,
        Message.query.filter_by(source='twitter'),
        show_hidden=with_replies)


@app.route('/forums/', defaults={'page': 1})
@app.route('/forums/page/<int:page>')
def show_forums(page):
    return show_listing('show_forums.html', page,
        Message.query.filter_by(source='forums'), per_page=10)


@app.route('/developer/<slug>/', defaults={'page': 1})
@app.route('/developer/<slug>/page/<int:page>')
def show_developer(slug, page):
    developer = Developer.query.filter_by(slug=slug).first_or_404()
    return show_listing('show_developer.html', page,
        Message.query.filter_by(developer=developer),
        context={'developer': developer})


@app.route('/my-favs/', defaults={'page': 1})
@app.route('/my-favs/page/<int:page>')
@require_login
def my_favorites(page):
    return redirect(url_for('favorites', page=page, slug=g.user.slug))


@app.route('/favs/<slug>/', defaults={'page': 1})
@app.route('/favs/<slug>/page/<int:page>')
def favorites(slug, page):
    id = from_base36(slug)
    if id is None:
        abort(404)
    user = User.query.filter_by(steam_id=unicode(id)).first_or_404()
    return show_listing('favorites.html', page, user.favorites,
                        context={'user': user})


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


@app.route('/login')
@oid.loginhandler
def login():
    if g.user is not None:
        return redirect(oid.get_next_url())
    return oid.try_login('http://steamcommunity.com/openid')


@app.route('/logout')
def logout():
    if g.user is not None:
        flash('You were logged out')
        g.user.logout()
    return redirect(oid.get_next_url())


@oid.after_login
def create_or_login(resp):
    match = _steam_id_re.search(resp.identity_url)
    if match is None:
        logger.error('Could not find steam ID for %r' % resp.identity_url)
        flash(u'Could not sign in.  Steam did not respond properly')
        return redirect(url_for('index'))
    g.user = User.get_or_create(match.group(1))
    db.session.commit()
    g.user.login()
    flash('You are logged in as %s' % g.user.nickname)
    return redirect(oid.get_next_url())


@app.route('/admin/', methods=['GET', 'POST'])
@require_admin
def admin():
    developers = Developer.query.order_by('-name').all()
    if request.method == 'POST':
        for dev in developers:
            dev.name = request.form['name_%d' % dev.id]
            dev.twitter_name = request.form['twitter_name_%d' % dev.id] or None
            dev.forum_name = request.form['forum_name_%d' % dev.id] or None
            dev.description = request.form['description_%d' % dev.id]
        new_dev = request.form['new_dev']
        if new_dev:
            dev = Developer(new_dev)
            db.session.add(dev)
        db.session.commit()
        flash('Changes saved')
        return redirect(request.base_url)
    return render_template('admin.html', developers=developers)


@app.route('/_nojs')
def no_javascript():
    return render_template('no_javascript.html')


@app.route('/_favorite', methods=['POST'])
@require_login
def update_favorite_status():
    message = Message.query.get(request.form['id'])
    if message is None:
        abort(400)
    try:
        if request.form['state'] == 'on':
            g.user.favorites.append(message)
        else:
            g.user.favorites.remove(message)
        db.session.commit()
    except Exception:
        abort(400)
    return 'OK'


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404
