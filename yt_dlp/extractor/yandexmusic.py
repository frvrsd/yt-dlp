import base64
import hashlib
import hmac
import itertools
import re
import time
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from .common import InfoExtractor
from ..networking import HEADRequest
from ..utils import (
    ExtractorError,
    float_or_none,
    int_or_none,
    join_nonempty,
    str_or_none,
    try_call,
)
from ..utils.traversal import traverse_obj


class YandexMusicBaseIE(InfoExtractor):
    _VALID_URL_BASE = r'https?://music\.yandex\.(?P<tld>ru|kz|ua|by|com|uz)'
    _API_BASE = 'https://api.music.yandex.net'
    _WEB_API_BASE = 'https://api.music.yandex.ru'
    _FRONTEND_HOME = 'https://music.yandex.ru/'
    # App-level HMAC secret from the music-web frontend (player.secretKey.web).
    # Stable across sessions; only changes when Yandex ships a new frontend.
    _SECRET_KEY = '7tvSmFbyf5hJnIHhCimDDD'
    _CODECS = 'flac,mp3'
    _TRANSPORT = 'raw'
    _CLIENT = 'YandexMusicWebNext/1.0.0'
    _KEY_CACHE = {'key': None, 'refresh_failed': False}
    _KEY_PATTERNS = (
        re.compile(r'secretKey\s*:\s*\{\s*web\s*:\s*"([A-Za-z0-9]{8,64})"'),
        re.compile(r'secretKey\s*:\s*"([A-Za-z0-9]{8,64})"'),
    )

    def _api_headers(self):
        return {
            'Accept': 'application/json',
            'Origin': 'https://music.yandex.ru',
            'Referer': 'https://music.yandex.ru/',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Retpath-Y': 'https://music.yandex.ru/',
            'x-request-id': str(uuid.uuid4()),
            'x-yandex-music-client': self._CLIENT,
            'accept-language': 'en',
        }

    def _call_api(self, path, item_id, note='Downloading JSON metadata',
                  query=None, data=None, fatal=True, headers=None):
        req_headers = self._api_headers()
        if headers:
            req_headers.update(headers)
        response = self._download_json(
            f'{self._API_BASE}/{path}', item_id, note, fatal=fatal,
            headers=req_headers, query=query, data=data)
        if not response:
            return response
        error = traverse_obj(response, ('error', ('message', 'name'), {str}, any))
        if error:
            raise ExtractorError(f'Yandex Music said: {error}', expected=True)
        return response.get('result', response)

    @staticmethod
    def _make_sign(ts, track_id, quality, codecs, transport, key):
        # Codecs are joined WITHOUT commas for signing; the URL uses commas.
        data = f'{ts}{track_id}{quality}{codecs.replace(",", "")}{transport}'
        digest = hmac.new(key.encode(), data.encode(), hashlib.sha256).digest()
        return base64.b64encode(digest).decode().rstrip('=')

    def _current_hmac_key(self):
        pinned = self._configuration_arg(
            'hmac_key', [None], ie_key='YandexMusic', casesense=True)[0]
        if pinned:
            return pinned
        if self._KEY_CACHE['key']:
            return self._KEY_CACHE['key']
        cached = try_call(lambda: self.cache.load('yandexmusic', 'hmac-key'))
        key = traverse_obj(cached, 'key', expected_type=str)
        if key:
            self._KEY_CACHE['key'] = key
            return key
        return self._SECRET_KEY

    def _save_hmac_key(self, key):
        self._KEY_CACHE['key'] = key
        self.cache.store('yandexmusic', 'hmac-key', {'key': key})

    def _frontend_chunk_urls(self, html):
        urls = set(re.findall(
            r'https://[^"\s]+?/static/chunks/[A-Za-z0-9_./()%-]+\.js', html))
        urls.update(re.findall(r'src="(https://[^"]+\.js)"', html))
        webpack = next((u for u in urls if 'webpack-' in u), None)
        if not webpack:
            return urls
        js = self._download_webpage(
            webpack, 'ym-frontend', note=False, fatal=False, errnote=False)
        if not js:
            return urls
        i = js.find('a.u=')
        if i == -1:
            return urls
        j = js.find(',a.', i + 10)
        seg = js[i:j if j != -1 else i + 6000]
        base = webpack.rsplit('/static/chunks/', 1)[0] + '/static/chunks/'
        for name in re.findall(r'"static/chunks/([^"]+\.js)"', seg):
            urls.add(base + name)
        for cid, hash_ in re.findall(
                r'(\d+)===e\?"static/chunks/"\+e\+"-([a-f0-9]+)\.js"', seg):
            urls.add(f'{base}{cid}-{hash_}.js')
        tables = re.findall(r'\(\{([^}]+)\}\)\[e\]', seg)
        if len(tables) >= 2:
            t_prefix = dict(re.findall(r'(\d+):"([a-f0-9]+)"', tables[-2]))
            t_suffix = dict(re.findall(r'(\d+):"([a-f0-9]+)"', tables[-1]))
            for cid, suffix in t_suffix.items():
                urls.add(f'{base}{t_prefix.get(cid, cid)}.{suffix}.js')
        return urls

    def _fetch_key_from_frontend(self):
        html = self._download_webpage(
            self._FRONTEND_HOME, 'ym-frontend',
            note='Refreshing Yandex Music signing key from frontend',
            fatal=False, errnote=False)
        if not html:
            return None
        urls = self._frontend_chunk_urls(html)
        if not urls:
            return None

        def _get(u):
            return self._download_webpage(
                u, 'ym-frontend', note=False, fatal=False, errnote=False)

        key = None
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_get, u) for u in urls]
            for fut in as_completed(futures):
                js = fut.result()
                if not js:
                    continue
                for pat in self._KEY_PATTERNS:
                    m = pat.search(js)
                    if m:
                        key = m.group(1)
                        break
                if key:
                    break
        if key is None:
            self._KEY_CACHE['refresh_failed'] = True
        return key

    def _get_file_info(self, track_id, quality):
        ts = str(int(time.time()))
        sign = self._make_sign(
            ts, track_id, quality, self._CODECS, self._TRANSPORT,
            self._current_hmac_key())
        url = (
            f'{self._WEB_API_BASE}/get-file-info?ts={ts}&trackId={track_id}'
            f'&quality={quality}&codecs={urllib.parse.quote(self._CODECS)}'
            f'&transports={self._TRANSPORT}&sign={urllib.parse.quote(sign)}')
        headers = self._api_headers()
        headers['x-yandex-music-without-invocation-info'] = '1'
        info = self._download_json(
            url, track_id,
            f'Downloading track stream info ({quality})',
            headers=headers, fatal=False, expected_status=(403,))
        if not isinstance(info, dict):
            body = self._download_webpage(
                url, track_id, note=False, fatal=False, errnote=False,
                headers=headers, expected_status=(403,)) or ''
            if 'not-allowed' in body:
                raise ExtractorError('not-allowed', expected=True)
            raise ExtractorError('Unable to get track stream info', expected=True)

        err = info.get('result') if isinstance(info.get('result'), dict) else info
        if traverse_obj(err, 'name') == 'track-download-info-error':
            message = err.get('message') or 'download info error'
            raise ExtractorError(message, expected=True)

        download_info = info.get('downloadInfo') or traverse_obj(info, ('result', 'downloadInfo'))
        if not isinstance(download_info, dict):
            raise ExtractorError('No download info in response', expected=True)
        return download_info

    def _stream_url(self, download_info):
        return (
            download_info.get('url')
            or traverse_obj(download_info, ('urls', 0, {str})))

    def _refresh_hmac_key(self):
        if self._configuration_arg(
                'hmac_key', [None], ie_key='YandexMusic', casesense=True)[0]:
            raise ExtractorError(
                'Yandex Music signing key rejected. Update hmac_key via '
                '--extractor-args "yandexmusic:hmac_key=..."',
                expected=True)
        if self._KEY_CACHE.get('refresh_failed'):
            raise ExtractorError(
                'Yandex Music signing key rejected and could not be refreshed. '
                'Pass a fresh key with --extractor-args "yandexmusic:hmac_key=..."',
                expected=True)
        old_key = self._current_hmac_key()
        new_key = self._fetch_key_from_frontend()
        if new_key and new_key != old_key:
            self._save_hmac_key(new_key)
            self.report_warning(
                f'Yandex Music signing key refreshed to {new_key!r}')
            return
        self._KEY_CACHE['refresh_failed'] = True
        raise ExtractorError(
            'Yandex Music signing key rejected and could not be refreshed',
            expected=True)

    def _extract_formats(self, track_id):
        download_info = None
        last_err = None
        key_refreshed = False
        for quality in ('lossless', 'nq'):
            try:
                download_info = self._get_file_info(track_id, quality)
                break
            except ExtractorError as e:
                last_err = e
                if str(e) == 'not-allowed':
                    if key_refreshed:
                        raise ExtractorError(
                            'Yandex Music signing key still rejected after refresh',
                            expected=True)
                    self._refresh_hmac_key()
                    key_refreshed = True
                    try:
                        download_info = self._get_file_info(track_id, quality)
                        break
                    except ExtractorError as retry_err:
                        last_err = retry_err
                        if str(retry_err) == 'not-allowed':
                            raise ExtractorError(
                                'Yandex Music signing key still rejected after refresh',
                                expected=True)
                        # Non-signature failure after refresh — try next quality.
                if quality == 'nq':
                    raise last_err
                self.report_warning(
                    f'Track {track_id}: {quality} unavailable, trying fallback ({last_err})')
                continue

        if not download_info:
            raise last_err or ExtractorError(
                'Unable to get track stream info', expected=True)

        stream_url = self._stream_url(download_info)
        if not stream_url:
            raise ExtractorError('No stream URL in download info', expected=True)

        served_quality = download_info.get('quality')
        if served_quality in ('preview', 'smart_preview'):
            self.report_warning(
                f'Track {track_id}: server served a {served_quality} stream. '
                'Pass fresh cookies from a logged-in Yandex Music session '
                '(--cookies) for full tracks')

        codec = download_info.get('codec') or 'mp3'
        abr = int_or_none(download_info.get('bitrate'))
        return [{
            'url': stream_url,
            'format_id': join_nonempty(codec, abr),
            'ext': 'flac' if codec == 'flac' else ('m4a' if codec == 'aac' else codec),
            'vcodec': 'none',
            'acodec': codec,
            'abr': abr,
        }], download_info

    def _warn_short_preview(self, track_id, duration_ms, download_info):
        if download_info.get('quality') in ('preview', 'smart_preview'):
            return
        bitrate = int_or_none(download_info.get('bitrate'))
        stream_url = self._stream_url(download_info)
        if not (duration_ms and bitrate and stream_url):
            return
        try:
            with self._downloader.urlopen(HEADRequest(stream_url)) as resp:
                content_length = int_or_none(resp.headers.get('Content-Length'))
        except Exception:
            return
        if not content_length:
            return
        est_ms = content_length * 8 / bitrate
        if est_ms < duration_ms * 0.5:
            self.report_warning(
                f'Track {track_id}: served stream is ~{est_ms / 1000:.0f}s '
                f'but metadata says {duration_ms / 1000:.0f}s — cookies may be stale')

    @staticmethod
    def _extract_artists(artists):
        names = traverse_obj(artists, (..., 'name', {str}))
        return ', '.join(names) or None

    @staticmethod
    def _cover_url(cover_uri):
        if not cover_uri:
            return None
        url = cover_uri.replace('%%', 'orig')
        if url.startswith('//'):
            return 'https:' + url
        if not url.startswith('http'):
            return 'https://' + url
        return url

    def _track_info(self, track):
        track_id = str_or_none(track.get('id') or track.get('realId'))
        title = track['title']
        album = traverse_obj(track, ('albums', 0, {dict})) or {}
        formats, download_info = self._extract_formats(track_id)
        duration_ms = int_or_none(track.get('durationMs'))
        self._warn_short_preview(track_id, duration_ms, download_info)

        artist = self._extract_artists(track.get('artists'))
        return {
            'id': track_id,
            'title': join_nonempty(artist, title, delim=' - '),
            'track': title,
            'artist': artist,
            'formats': formats,
            'thumbnail': self._cover_url(track.get('coverUri') or album.get('coverUri')),
            'duration': float_or_none(duration_ms, 1000),
            'filesize': int_or_none(track.get('fileSize')) or None,
            'album': album.get('title'),
            'album_artist': self._extract_artists(album.get('artists')),
            'release_year': int_or_none(album.get('year')),
            'genre': album.get('genre'),
            'disc_number': traverse_obj(album, ('trackPosition', 'volume', {int_or_none})),
            'track_number': traverse_obj(album, ('trackPosition', 'index', {int_or_none})),
        }


class YandexMusicTrackIE(YandexMusicBaseIE):
    IE_NAME = 'yandexmusic:track'
    IE_DESC = 'Яндекс.Музыка - Трек'
    _VALID_URL = (
        rf'{YandexMusicBaseIE._VALID_URL_BASE}'
        rf'/(?:album/(?P<album_id>\d+)/)?track/(?P<id>\d+)')

    _TESTS = [{
        'url': 'https://music.yandex.ru/album/43558320/track/154831593',
        'info_dict': {
            'id': '154831593',
            'ext': 'mp3',
            'title': 'Pikhto - Look, She Escapes',
            'track': 'Look, She Escapes',
            'artist': 'Pikhto',
            'album': 'Inner Child',
            'album_artist': 'Pikhto',
            'release_year': 2026,
            'duration': float,
            'thumbnail': r're:https?://.+',
        },
        'params': {'skip_download': True},
        'skip': 'Requires Yandex Music cookies (--cookies)',
    }, {
        'url': 'http://music.yandex.com/album/540508/track/4878838',
        'only_matching': True,
    }]

    def _real_extract(self, url):
        track_id = self._match_id(url)
        track = traverse_obj(
            self._call_api(f'tracks/{track_id}', track_id, 'Downloading track JSON'),
            (0, {dict}))
        if not track:
            raise ExtractorError('Unable to find track', expected=True)
        if track.get('error') == 'not-found':
            raise ExtractorError(f'Track {track_id} not found', expected=True)
        return self._track_info(track)


class YandexMusicPlaylistBaseIE(YandexMusicBaseIE):
    def _resolve_tracks(self, tracks, item_id):
        """Resolve playlist entries to full track dicts, preserving order."""
        result = [None] * len(tracks)
        missing_ids = []
        missing_indices = []
        for i, entry in enumerate(tracks):
            track = entry.get('track') if isinstance(entry, dict) else None
            if track:
                result[i] = track
                continue
            track_id = str_or_none(
                entry.get('id') if isinstance(entry, dict) else entry)
            if track_id:
                missing_ids.append(track_id)
                missing_indices.append(i)

        resolved_by_id = {}
        for start in itertools.count(0, 250):
            chunk = missing_ids[start:start + 250]
            if not chunk:
                break
            resolved = self._call_api(
                'tracks', item_id, f'Downloading tracks JSON ({start + len(chunk)})',
                data=f'track-ids={",".join(chunk)}'.encode(),
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            for track in resolved or []:
                track_id = str_or_none(track.get('id') or track.get('realId'))
                if track_id and track_id not in resolved_by_id:
                    resolved_by_id[track_id] = track

        for idx, track_id in zip(missing_indices, missing_ids):
            track = resolved_by_id.get(track_id)
            if track:
                result[idx] = track

        return [track for track in result if track]

    def _build_playlist(self, tracks):
        for track in tracks:
            track_id = str_or_none(track.get('id') or track.get('realId'))
            album_id = traverse_obj(track, ('albums', 0, 'id', {str_or_none}))
            if not (track_id and album_id):
                continue
            yield self.url_result(
                f'https://music.yandex.ru/album/{album_id}/track/{track_id}',
                YandexMusicTrackIE, track_id,
                traverse_obj(track, ('title', {str})))


class YandexMusicAlbumIE(YandexMusicPlaylistBaseIE):
    IE_NAME = 'yandexmusic:album'
    IE_DESC = 'Яндекс.Музыка - Альбом'
    _VALID_URL = rf'{YandexMusicBaseIE._VALID_URL_BASE}/album/(?P<id>\d+)'

    _TESTS = [{
        'url': 'https://music.yandex.ru/album/43558320',
        'info_dict': {
            'id': '43558320',
            'title': 'Pikhto - Inner Child (2026)',
        },
        'playlist_mincount': 1,
        'skip': 'Requires Yandex Music cookies (--cookies)',
    }]

    @classmethod
    def suitable(cls, url):
        return False if YandexMusicTrackIE.suitable(url) else super().suitable(url)

    def _real_extract(self, url):
        album_id = self._match_id(url)
        album = self._call_api(
            f'albums/{album_id}/with-tracks', album_id, 'Downloading album JSON')
        if not album:
            raise ExtractorError(f'Album {album_id} not found', expected=True)

        tracks = [track for volume in album.get('volumes') or [] for track in volume]
        title = album.get('title')
        artist = traverse_obj(album, ('artists', 0, 'name', {str}))
        if artist:
            title = f'{artist} - {title}'
        if album.get('year'):
            title += f' ({album["year"]})'

        return self.playlist_result(
            self._build_playlist(tracks), str(album['id']), title)


class YandexMusicPlaylistIE(YandexMusicPlaylistBaseIE):
    IE_NAME = 'yandexmusic:playlist'
    IE_DESC = 'Яндекс.Музыка - Плейлист'
    _VALID_URL = (
        rf'{YandexMusicBaseIE._VALID_URL_BASE}'
        rf'/users/(?P<user>[^/]+)/playlists/(?P<id>\d+)')

    _TESTS = [{
        'url': 'https://music.yandex.ru/users/music.partners/playlists/1245',
        'info_dict': {
            'id': '1245',
        },
        'playlist_mincount': 1,
        'skip': 'Requires Yandex Music cookies (--cookies)',
    }, {
        'url': 'https://music.yandex.ru/users/ya.playlist/playlists/1036',
        'only_matching': True,
    }]

    def _real_extract(self, url):
        user, playlist_id = self._match_valid_url(url).group('user', 'id')
        playlist = self._call_api(
            f'users/{user}/playlists/{playlist_id}', playlist_id,
            'Downloading playlist JSON')
        if not playlist:
            raise ExtractorError(f'Playlist {playlist_id} not found', expected=True)

        tracks = self._resolve_tracks(playlist.get('tracks') or [], playlist_id)
        return self.playlist_result(
            self._build_playlist(tracks), playlist_id,
            playlist.get('title'), playlist.get('description'))


class YandexMusicArtistBaseIE(YandexMusicPlaylistBaseIE):
    def _artist_name(self, artist_id):
        return traverse_obj(self._call_api(
            f'artists/{artist_id}/brief-info', artist_id,
            'Downloading artist brief info', fatal=False),
            ('artist', 'name', {str}))


class YandexMusicArtistTracksIE(YandexMusicArtistBaseIE):
    IE_NAME = 'yandexmusic:artist:tracks'
    IE_DESC = 'Яндекс.Музыка - Артист - Треки'
    _VALID_URL = rf'{YandexMusicBaseIE._VALID_URL_BASE}/artist/(?P<id>\d+)/tracks'

    _TESTS = [{
        'url': 'https://music.yandex.ru/artist/21022190/tracks',
        'info_dict': {
            'id': '21022190',
        },
        'playlist_mincount': 1,
        'skip': 'Requires Yandex Music cookies (--cookies)',
    }]

    def _real_extract(self, url):
        artist_id = self._match_id(url)
        tracks = []
        for page in itertools.count(0):
            data = self._call_api(
                f'artists/{artist_id}/tracks', artist_id,
                f'Downloading artist tracks page {page + 1}',
                query={'page': page, 'page-size': 100}) or {}
            page_tracks = data.get('tracks') or []
            tracks.extend(page_tracks)
            total = traverse_obj(data, ('pager', 'total', {int_or_none}))
            if not page_tracks or (total is not None and len(tracks) >= total):
                break

        artist = self._artist_name(artist_id)
        return self.playlist_result(
            self._build_playlist(tracks), artist_id,
            join_nonempty(artist or artist_id, 'Треки', delim=' - '))


class YandexMusicArtistAlbumsIE(YandexMusicArtistBaseIE):
    IE_NAME = 'yandexmusic:artist:albums'
    IE_DESC = 'Яндекс.Музыка - Артист - Альбомы'
    _VALID_URL = rf'{YandexMusicBaseIE._VALID_URL_BASE}/artist/(?P<id>\d+)/albums'

    _TESTS = [{
        'url': 'https://music.yandex.ru/artist/21022190/albums',
        'info_dict': {
            'id': '21022190',
        },
        'playlist_mincount': 1,
        'skip': 'Requires Yandex Music cookies (--cookies)',
    }]

    def _real_extract(self, url):
        artist_id = self._match_id(url)
        albums = []
        for page in itertools.count(0):
            data = self._call_api(
                f'artists/{artist_id}/direct-albums', artist_id,
                f'Downloading artist albums page {page + 1}',
                query={'page': page, 'page-size': 100}) or {}
            page_albums = data.get('albums') or []
            albums.extend(page_albums)
            total = traverse_obj(data, ('pager', 'total', {int_or_none}))
            if not page_albums or (total is not None and len(albums) >= total):
                break

        entries = []
        for album in albums:
            album_id = traverse_obj(album, ('id', {str_or_none}))
            if album_id:
                entries.append(self.url_result(
                    f'https://music.yandex.ru/album/{album_id}',
                    YandexMusicAlbumIE, album_id))

        artist = self._artist_name(artist_id)
        return self.playlist_result(
            entries, artist_id,
            join_nonempty(artist or artist_id, 'Альбомы', delim=' - '))
