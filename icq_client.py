#!/usr/bin/env python3

# ICQClient
#
# Copyright 2026 BitByByte (tankwars92)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import annotations

import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union


MAX_DATA_LEN = 8192
TFLAPSZ = 6
TSNACSZ = 10
ICQ_PROTOCOL_VER = 0x0008
ICQ_CLIENT_VER_MAJOR = 1
ICQ_CLIENT_VER_MINOR = 21

S_ONLINE = 0x00000000
S_INVISIBLE = 0x00000100
S_AWAY = 0x00000001
S_NA = 0x00000005
L_S_NA = 0x00000004
S_OCCUPIED = 0x00000011
L_S_OCCUPIED = 0x00000010
S_DND = 0x00000013
L_S_DND = 0x00000012
S_FFC = 0x00000020
S_OFFLINE = 0xFFFFFFFF
SF_BIRTH = 0x00080000

S_SHOWIP = 0x00020000
S_WEBAWARE = 0x00030000
S_ALLOWDCONN = 0x00000000
S_ALLOWDAUTH = 0x10000000
S_ALLOWDLIST = 0x20000000

M_PLAIN = 0x01
M_CHAT = 0x02
M_FILE = 0x03
M_URL = 0x04
M_AUTH_REQ = 0x06
M_AUTH_DENIED = 0x07
M_AUTH_GIVEN = 0x08
M_WEB_PAGE = 0x0D
M_EMAIL_EXPRESS = 0x0E
M_CONTACTS = 0x13
M_ADVANCED = 0x1A

GEN_FEMALE = 1
GEN_MALE = 2

CMD_ACKOFFMSG = 0x3E
CMD_REQOFFMSG = 0x3C
CMD_REQINFO = 0x7D0

U_NORMAL = 0x0000
U_VISIBLE_LIST = 0x0002
U_INVISIBLE_LIST = 0x0003
U_IGNORE_LIST = 0x000E

ACC_NORMAL = 0x0
ACC_NO_OCCUPIED = 0x9
ACC_NO_DND = 0xA
ACC_AWAY = 0x4
ACC_NA = 0xE
ACC_CONTACTLST = 0xC

GET_AWAY = 0xE8
GET_OCCUPIED = 0xE9
GET_NA = 0xEA
GET_DND = 0xEB
GET_FFC = 0xEC

MFLAG_NORMAL = 0x01
MFLAG_AUTO = 0x03
MFLG_MULTI = 0x80

BUDDY_NORMAL = 0x0000
BUDDY_GROUP = 0x0001
BUDDY_IGNORE = 0x000E
BUDDY_INVISIBLE = 0x0003
BUDDY_VISIBLE = 0x0002

ERRSSL_NOTFOUND = 0x0002
ERRSSL_EXISTS = 0x0003
ERRSSL_AUTH = 0x000E
ERRSSL_OTHER = 0x000A
ERRSSL_NOERROR = 0x0000

CAPS_ICQ = 0x01
CAPS_ICQRTF = 0x02
CAPS_ICQSERVERRELAY = 0x04
CAPS_2001 = 0x08
CAPS_2001a = 0x10

TXOR_DATA = bytes([
    0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
    0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C,
])

FILE_SIGNATURE = bytes([
    0xF0, 0x2D, 0x12, 0xD9, 0x30, 0x91, 0xD3, 0x11,
    0x8D, 0xD7, 0x00, 0x10, 0x4B, 0x06, 0x46, 0x2E,
])

CONTACTS_SIGNATURE = bytes([
    0x2A, 0x0E, 0x7D, 0x46, 0x76, 0x76, 0xD4, 0x11,
    0xBC, 0xE6, 0x00, 0x04, 0xAC, 0x96, 0x1E, 0xA6,
])

CAPS_SETUSERINFO = bytes([
    0x09, 0x46, 0x13, 0x49, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
    0x97, 0xB1, 0x27, 0x51, 0x24, 0x3C, 0x43, 0x34, 0xAD, 0x22, 0xD6, 0xAB, 0xF7, 0x3F, 0x14, 0x92,
    0x2E, 0x7A, 0x64, 0x75, 0xFA, 0xDF, 0x4D, 0xC8, 0x88, 0x6F, 0xEA, 0x35, 0x95, 0xFD, 0xB6, 0xDF,
    0x09, 0x46, 0x13, 0x44, 0x4C, 0x7F, 0x11, 0xD1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
])

CAPABILITIES_MSG = CAPS_SETUSERINFO[:16]

CLI_READY_BUF = bytes([
    0x00, 0x01, 0x00, 0x03, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x13, 0x00, 0x02, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x04, 0x7B,
    0x00, 0x03, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x15, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x04, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x06, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x09, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x0A, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
    0x00, 0x0B, 0x00, 0x01, 0x01, 0x10, 0x04, 0x7B,
])

MSG_GUID = "{97B12751-243C-4334-AD22-D6ABF73F1492}"


class ErrorType(IntEnum):
    ERR_SOCKET = 0
    ERR_INTERNAL = 1
    ERR_WARNING = 2
    ERR_PROXY = 3
    ERR_PROTOCOL = 4
    ERR_CONNTIMEOUT = 5
    ERR_LOGIN = 6


class ProxyType(IntEnum):
    P_NONE = 0
    P_SOCKS4 = 1
    P_SOCKS5 = 2
    P_HTTPS = 3
    P_HTTP = 4


class InfoType(IntEnum):
    INFO_GENERAL = 0
    INFO_MORE = 1
    INFO_ABOUT = 2
    INFO_PASSWORD = 3


class DbType(IntEnum):
    DB_ICQ = 0
    DB_MIRANDA = 1


class ICQLangType(IntEnum):
    LANG_EN = 0
    LANG_RU = 1


@dataclass
class FlapHdr:
    ident: int = 0
    ch_id: int = 0
    seq: int = 0
    data_len: int = 0


@dataclass
class SnacHdr:
    family: int = 0
    sub_type: int = 0
    flags: int = 0
    req_id: int = 0


@dataclass
class FTRequestRec:
    req_type: int = 0
    i_time: int = 0
    i_random_id: int = 0
    uin: int = 0
    description: str = ""
    file_name: str = ""
    file_size: int = 0
    seq: int = 0
    port: int = 0


@dataclass
class FTStartRec:
    uin: int = 0
    files_count: int = 0
    current: int = 0
    speed: int = 0


@dataclass
class SendFileRec:
    uin: int = 0
    nick: str = ""
    seq: int = 0
    files: List[str] = field(default_factory=list)
    files_current: int = 0
    files_count: int = 0
    file_path: str = ""
    file_name: str = ""
    file_description: str = ""
    file_size: int = 0
    total_size: int = 0
    port: int = 0
    speed: int = 0


@dataclass
class PortRange:
    first: int = 0
    last: int = 0


@dataclass
class UINEntry:
    uin: int = 0
    nick: str = ""
    c_type: int = 0
    c_tag: int = 0
    c_group_id: int = 0
    cellular: str = ""
    authorized: bool = False

COUNTRIES = {
    1: 'USA',
    7: 'Russia',
    20: 'Egypt',
    27: 'South Africa',
    30: 'Greece',
    31: 'Netherlands',
    32: 'Belgium',
    33: 'France',
    34: 'Spain',
    36: 'Hungary',
    39: 'Italy',
    40: 'Romania',
    41: 'Switzerland',
    42: 'Czech Republic',
    43: 'Austria',
    44: 'United Kingdom',
    45: 'Denmark',
    46: 'Sweden',
    47: 'Norway',
    48: 'Poland',
    49: 'Germany',
    51: 'Peru',
    52: 'Mexico',
    53: 'Cuba',
    54: 'Argentina',
    55: 'Brazil',
    56: 'Chile',
    57: 'Colombia',
    58: 'Venezuela',
    60: 'Malaysia',
    61: 'Australia',
    62: 'Indonesia',
    63: 'Philippines',
    64: 'New Zealand',
    65: 'Singapore',
    66: 'Thailand',
    81: 'Japan',
    82: 'Korea (Republic of)',
    84: 'Vietnam',
    86: 'China',
    90: 'Turkey',
    91: 'India',
    92: 'Pakistan',
    93: 'Afghanistan',
    94: 'Sri Lanka',
    95: 'Myanmar',
    98: 'Iran',
    101: 'Anguilla',
    102: 'Antigua',
    103: 'Bahamas',
    104: 'Barbados',
    105: 'Bermuda',
    106: 'British Virgin Islands',
    107: 'Canada',
    108: 'Cayman Islands',
    109: 'Dominica',
    110: 'Dominican Republic',
    111: 'Grenada',
    112: 'Jamaica',
    113: 'Montserrat',
    114: 'Nevis',
    115: 'St. Kitts',
    116: 'St. Vincent and the Grenadines',
    117: 'Trinidad and Tobago',
    118: 'Turks and Caicos Islands',
    120: 'Barbuda',
    121: 'Puerto Rico',
    122: 'Saint Lucia',
    123: 'United States Virgin Islands',
    212: 'Morocco',
    213: 'Algeria',
    216: 'Tunisia',
    218: 'Libya',
    220: 'Gambia',
    221: 'Senegal Republic',
    222: 'Mauritania',
    223: 'Mali',
    224: 'Guinea',
    225: 'Ivory Coast',
    226: 'Burkina Faso',
    227: 'Niger',
    228: 'Togo',
    229: 'Benin',
    230: 'Mauritius',
    231: 'Liberia',
    232: 'Sierra Leone',
    233: 'Ghana',
    234: 'Nigeria',
    235: 'Chad',
    236: 'Central African Republic',
    237: 'Cameroon',
    238: 'Cape Verde Islands',
    239: 'Sao Tome and Principe',
    240: 'Equatorial Guinea',
    241: 'Gabon',
    242: 'Congo',
    243: 'Dem. Rep. of the Congo',
    244: 'Angola',
    245: 'Guinea-Bissau',
    246: 'Diego Garcia',
    247: 'Ascension Island',
    248: 'Seychelle Islands',
    249: 'Sudan',
    250: 'Rwanda',
    251: 'Ethiopia',
    252: 'Somalia',
    253: 'Djibouti',
    254: 'Kenya',
    255: 'Tanzania',
    256: 'Uganda',
    257: 'Burundi',
    258: 'Mozambique',
    260: 'Zambia',
    261: 'Madagascar',
    262: 'Reunion Island',
    263: 'Zimbabwe',
    264: 'Namibia',
    265: 'Malawi',
    266: 'Lesotho',
    267: 'Botswana',
    268: 'Swaziland',
    269: 'Mayotte Island',
    290: 'St. Helena',
    291: 'Eritrea',
    297: 'Aruba',
    298: 'Faeroe Islands',
    299: 'Greenland',
    350: 'Gibraltar',
    351: 'Portugal',
    352: 'Luxembourg',
    353: 'Ireland',
    354: 'Iceland',
    355: 'Albania',
    356: 'Malta',
    357: 'Cyprus',
    358: 'Finland',
    359: 'Bulgaria',
    370: 'Lithuania',
    371: 'Latvia',
    372: 'Estonia',
    373: 'Moldova',
    374: 'Armenia',
    375: 'Belarus',
    376: 'Andorra',
    377: 'Monaco',
    378: 'San Marino',
    379: 'Vatican City',
    380: 'Ukraine',
    381: 'Yugoslavia',
    385: 'Croatia',
    386: 'Slovenia',
    387: 'Bosnia and Herzegovina',
    389: 'F.Y.R.O.M. (Former Yugoslav Republic of Macedonia)',
    500: 'Falkland Islands',
    501: 'Belize',
    502: 'Guatemala',
    503: 'El Salvador',
    504: 'Honduras',
    505: 'Nicaragua',
    506: 'Costa Rica',
    507: 'Panama',
    508: 'St. Pierre and Miquelon',
    509: 'Haiti',
    590: 'Guadeloupe',
    591: 'Bolivia',
    592: 'Guyana',
    593: 'Ecuador',
    594: 'French Guiana',
    595: 'Paraguay',
    596: 'Martinique',
    597: 'Suriname',
    598: 'Uruguay',
    599: 'Netherlands Antilles',
    670: 'Saipan Island',
    671: 'Guam',
    672: 'Christmas Island',
    673: 'Brunei',
    674: 'Nauru',
    675: 'Papua New Guinea',
    676: 'Tonga',
    677: 'Solomon Islands',
    678: 'Vanuatu',
    679: 'Fiji Islands',
    680: 'Palau',
    681: 'Wallis and Futuna Islands',
    682: 'Cook Islands',
    683: 'Niue',
    684: 'American Samoa',
    685: 'Western Samoa',
    686: 'Kiribati Republic',
    687: 'New Caledonia',
    688: 'Tuvalu',
    689: 'French Polynesia',
    690: 'Tokelau',
    691: 'Micronesia, Federated States of',
    692: 'Marshall Islands',
    705: 'Kazakhstan',
    706: 'Kyrgyz Republic',
    708: 'Tajikistan',
    709: 'Turkmenistan',
    711: 'Uzbekistan',
    800: 'International Freephone Service',
    850: 'Korea (North)',
    852: 'Hong Kong',
    853: 'Macau',
    855: 'Cambodia',
    856: 'Laos',
    870: 'INMARSAT',
    871: 'INMARSAT (Atlantic-East)',
    872: 'INMARSAT (Pacific)',
    873: 'INMARSAT (Indian)',
    874: 'INMARSAT (Atlantic-West)',
    880: 'Bangladesh',
    886: 'Taiwan, Republic of China',
    960: 'Maldives',
    961: 'Lebanon',
    962: 'Jordan',
    963: 'Syria',
    964: 'Iraq',
    965: 'Kuwait',
    966: 'Saudi Arabia',
    967: 'Yemen',
    968: 'Oman',
    971: 'United Arab Emirates',
    972: 'Israel',
    973: 'Bahrain',
    974: 'Qatar',
    975: 'Bhutan',
    976: 'Mongolia',
    977: 'Nepal',
    994: 'Azerbaijan',
    995: 'Georgia',
    2691: 'Comoros',
    4101: 'Liechtenstein',
    4201: 'Slovak Republic',
    5399: 'Guantanamo Bay',
    5901: 'French Antilles',
    6101: 'Cocos-Keeling Islands',
    6701: 'Rota Island',
    6702: 'Tinian Island',
    6721: 'Australian Antarctic Territory',
    6722: 'Norfolk Island',
    9999: 'Unknown',
    65535: 'None',
}

LANGUAGES = {
    0: '',
    1: 'Arabic',
    2: 'Bhojpuri',
    3: 'Bulgarian',
    4: 'Burmese',
    5: 'Cantonese',
    6: 'Catalan',
    7: 'Chinese',
    8: 'Croatian',
    9: 'Czech',
    10: 'Danish',
    11: 'Dutch',
    12: 'English',
    13: 'Esperanto',
    14: 'Estonian',
    15: 'Farci',
    16: 'Finnish',
    17: 'French',
    18: 'Gaelic',
    19: 'German',
    20: 'Greek',
    21: 'Hebrew',
    22: 'Hindi',
    23: 'Hungarian',
    24: 'Icelandic',
    25: 'Indonesian',
    26: 'Italian',
    27: 'Japanese',
    28: 'Khmer',
    29: 'Korean',
    30: 'Lao',
    31: 'Latvian',
    32: 'Lithuanian',
    33: 'Malay',
    34: 'Norwegian',
    35: 'Polish',
    36: 'Portuguese',
    37: 'Romanian',
    38: 'Russian',
    39: 'Serbo-Croatian',
    40: 'Slovak',
    41: 'Slovenian',
    42: 'Somali',
    43: 'Spanish',
    44: 'Swahili',
    45: 'Swedish',
    46: 'Tagalog',
    47: 'Tatar',
    48: 'Thai',
    49: 'Turkish',
    50: 'Ukrainian',
    51: 'Urdu',
    52: 'Vietnamese',
    53: 'Yiddish',
    54: 'Yoruba',
    55: 'Afrikaans',
    56: 'Bosnian',
    57: 'Persian',
    58: 'Albanian',
    59: 'Armenian',
    60: 'Punjabi',
    61: 'Chamorro',
    62: 'Mongolian',
    63: 'Mandarin',
    64: 'Taiwanese',
    65: 'Macedonian',
    66: 'Sindhi',
    67: 'Welsh',
    68: 'Azerbaijani',
    69: 'Kurdish',
    70: 'Gujarati',
    71: 'Tamil',
    72: 'Belorussian',
    255: 'Unknown',
}

INTERESTS = {
    100: 'Art',
    101: 'Cars',
    102: 'Celebrity Fans',
    103: 'Collections',
    104: 'Computers',
    105: 'Culture & Literature',
    106: 'Fitness',
    107: 'Games',
    108: 'Hobbies',
    109: 'ICQ - Providing Help',
    110: 'Internet',
    111: 'Lifestyle',
    112: 'Movies/TV',
    113: 'Music',
    114: 'Outdoor Activities',
    115: 'Parenting',
    116: 'Pets/Animals',
    117: 'Religion',
    118: 'Science/Technology',
    119: 'Skills',
    120: 'Sports',
    121: 'Web Design',
    122: 'Nature and Environment',
    123: 'News & Media',
    124: 'Government',
    125: 'Business & Economy',
    126: 'Mystics',
    127: 'Travel',
    128: 'Astronomy',
    129: 'Space',
    130: 'Clothing',
    131: 'Parties',
    132: 'Women',
    133: 'Social science',
    134: '60',
    135: '70',
    136: '80',
    137: '50',
    138: 'Finance and corporate',
    139: 'Entertainment',
    140: 'Consumer electronics',
    141: 'Retail stores',
    142: 'Health and beauty',
    143: 'Media',
    144: 'Household products',
    145: 'Mail order catalog',
    146: 'Business services',
    147: 'Audio and visual',
    148: 'Sporting and athletic',
    149: 'Publishing',
    150: 'Home automation',
}

OCCUPATIONS = {
    1: 'Academic',
    2: 'Administrative',
    3: 'Art/Entertainment',
    4: 'College Student',
    5: 'Computers',
    6: 'Community & Social',
    7: 'Education',
    8: 'Engineering',
    9: 'Financial Services',
    10: 'Government',
    11: 'High School Student',
    12: 'Home',
    13: 'ICQ - Providing Help',
    14: 'Law',
    15: 'Managerial',
    16: 'Manufacturing',
    17: 'Medical/Health',
}

PASTS = {
    300: 'Elementary School',
    301: 'High School',
    302: 'College',
    303: 'University',
    304: 'Military',
    305: 'Past Work Place',
    306: 'Past Organization',
    399: 'Other',
}

ORGANIZATIONS = {
    200: 'Alumni Org.',
    201: 'Charity Org.',
    202: 'Club/Social Org.',
    203: 'Community Org.',
    204: 'Cultural Org.',
    205: 'Fan Clubs',
    206: 'Fraternity/Sorority',
    207: 'Hobbyists Org.',
    208: 'International Org.',
    209: 'Nature and Environment Org.',
    210: 'Professional Org.',
    211: 'Scientific/Technical Org.',
    212: 'Self Improvement Group',
    213: 'Spiritual/Religious Org.',
    214: 'Sports Org.',
    215: 'Support Org.',
    216: 'Trade and Business Org.',
    217: 'Union',
    218: 'Volunteer Org.',
    299: 'Other',
}

def swap16(value: int) -> int:
    return struct.unpack(">H", struct.pack("<H", value & 0xFFFF))[0]


def swap32(value: int) -> int:
    return struct.unpack(">I", struct.pack("<I", value & 0xFFFFFFFF))[0]


ICQ_MESSAGE_ENCODING = "cp1251"


def icq_encode(text: str, encoding: str = ICQ_MESSAGE_ENCODING) -> bytes:
    return text.encode(encoding, errors="replace")


def icq_decode(data: bytes, encoding: str = ICQ_MESSAGE_ENCODING) -> str:
    return data.decode(encoding, errors="replace")


def icq_encrypt_pass_str(password: str) -> bytes:
    raw = password.encode("ascii", errors="replace")
    out = bytearray(raw)
    for i, b in enumerate(out):
        out[i] = b ^ TXOR_DATA[i % len(TXOR_DATA)]
    return bytes(out)


def status_to_int(value: int) -> int:
    if value == S_OFFLINE:
        return S_OFFLINE
    if (value & S_DND) == S_DND:
        return S_DND
    if (value & S_OCCUPIED) == S_OCCUPIED:
        return S_OCCUPIED
    if (value & S_NA) == S_NA:
        return S_NA
    if (value & L_S_OCCUPIED) == L_S_OCCUPIED:
        return S_OCCUPIED
    if (value & L_S_DND) == L_S_DND:
        return S_DND
    if (value & S_AWAY) == S_AWAY:
        return S_AWAY
    if (value & S_INVISIBLE) == S_INVISIBLE:
        return S_INVISIBLE
    if (value & S_FFC) == S_FFC:
        return S_FFC
    if (value & L_S_NA) == L_S_NA:
        return S_NA
    return S_ONLINE


def status_to_str(value: int) -> str:
    s = status_to_int(value)
    return {
        S_DND: "DND",
        S_OCCUPIED: "Occupied",
        S_NA: "N/A",
        S_AWAY: "Away",
        S_INVISIBLE: "Invisible",
        S_FFC: "FFC",
        S_OFFLINE: "Offline",
    }.get(s, "Online")


def country_to_str(value: int) -> str:
    return COUNTRIES.get(value, str(value))


def language_to_str(value: int) -> str:
    return LANGUAGES.get(value, str(value))


def occupation_to_str(value: int) -> str:
    return OCCUPATIONS.get(value, str(value))


def interest_to_str(value: int) -> str:
    return INTERESTS.get(value, str(value))


def past_to_str(value: int) -> str:
    return PASTS.get(value, str(value))


def affiliation_to_str(value: int) -> str:
    return ORGANIZATIONS.get(value, str(value))


def str_to_language_i(value: str) -> int:
    for k, v in LANGUAGES.items():
        if v == value:
            return k
    return 0


def str_to_country_i(value: str) -> int:
    for k, v in COUNTRIES.items():
        if v == value:
            return k
    return 0


def str_to_interest_i(value: str) -> int:
    for k, v in INTERESTS.items():
        if v == value:
            return k
    return 0


def str_to_occupation_i(value: str) -> int:
    for k, v in OCCUPATIONS.items():
        if v == value:
            return k
    return 0


def str_to_past_i(value: str) -> int:
    for k, v in PASTS.items():
        if v == value:
            return k
    return 0


def str_to_organization_i(value: str) -> int:
    for k, v in ORGANIZATIONS.items():
        if v == value:
            return k
    return 0


def extract_name(value: str) -> str:
    if "=" in value:
        return value.split("=", 1)[0]
    return value


def extract_value(value: str) -> str:
    if "=" in value:
        return value.split("=", 1)[1]
    return ""


def parse_contacts(value: str) -> List[str]:
    result: List[str] = []
    pos = value.find("\xfe")
    if pos < 0 or pos + 1 >= len(value):
        return result
    l = 0
    fname = ""
    fuin = ""
    for ch in value[pos + 1 :]:
        if ch == "\xfe":
            l += 1
        else:
            if l % 2 == 0:
                fname += ch
            else:
                fuin += ch
        if l == 2:
            if fname and fuin:
                result.append(f"{fname}={fuin}")
            fname = ""
            fuin = ""
            l = 0
    return result


def make_contacts_str(contacts: Sequence[str]) -> str:
    parts: List[str] = []
    count = 0
    for item in contacts:
        name = extract_name(item)
        if not name:
            continue
        val = extract_value(item) or name
        parts.extend([name, val])
        count += 1
    return f"{count}\xfe" + "\xfe".join(parts) + ("\xfe" if parts else "")


def rtf2plain(source: str) -> str:
    if not source or source[0] != "{":
        return source
    out: List[str] = []
    i = 0
    while i < len(source):
        ch = source[i]
        if ch == "{":
            i += 1
            depth = 1
            while i < len(source) and depth:
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                elif source[i] not in "\\":
                    out.append(source[i])
                i += 1
        elif ch == "}":
            i += 1
        elif ch == "\\":
            i += 1
            if i < len(source) and source[i] in " \n\r\t":
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def ucs2be_to_str(value: bytes) -> str:
    if len(value) < 2:
        return ""
    return value.decode("utf-16-be", errors="replace")


def str_to_utf8(value: str) -> bytes:
    return value.encode("utf-8")


def utf8_to_str(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def get_xml_entry(tag: str, msg: str) -> str:
    open_tag = f"<{tag}>"
    close_tag = f"</{tag}>"
    start = msg.find(open_tag)
    if start < 0:
        return ""
    start += len(open_tag)
    end = msg.find(close_tag, start)
    if end < 0:
        return ""
    return msg[start:end]


def dump_packet(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def snac_to_str(family: int, sub_type: int) -> str:
    return f"SNAC({family:04X},{sub_type:04X})"


class RawPkt:
    __slots__ = ("buf", "pos")

    def __init__(self) -> None:
        self.buf = bytearray()
        self.pos = 0

    def clear(self) -> None:
        self.buf.clear()
        self.pos = 0

    def reset_read(self) -> None:
        self.pos = 0

    def bytes(self) -> bytes:
        return bytes(self.buf)

    def _ensure(self, extra: int) -> None:
        if len(self.buf) + extra > MAX_DATA_LEN:
            raise ValueError("packet too large")


def pkt_add_data(pkt: RawPkt, data: bytes) -> None:
    if not data:
        return
    pkt._ensure(len(data))
    pkt.buf.extend(reversed(data))


def pkt_add_arr_buf(pkt: RawPkt, data: bytes) -> None:
    if not data:
        return
    pkt._ensure(len(data))
    pkt.buf.extend(data)


def pkt_int(pkt: RawPkt, value: int, size: int) -> None:
    if size <= 0:
        return
    mask = (1 << (size * 8)) - 1
    pkt_add_arr_buf(pkt, (value & mask).to_bytes(size, "big"))


def pkt_lint(pkt: RawPkt, value: int, size: int) -> None:
    if size <= 0:
        return
    mask = (1 << (size * 8)) - 1
    pkt_add_arr_buf(pkt, (value & mask).to_bytes(size, "little"))


def pkt_str(pkt: RawPkt, s: Union[str, bytes], encoding: str = ICQ_MESSAGE_ENCODING) -> None:
    if isinstance(s, str):
        data = icq_encode(s, encoding)
    else:
        data = s
    pkt_add_arr_buf(pkt, data)


def pkt_lstr(pkt: RawPkt, s: Union[str, int]) -> None:
    if isinstance(s, int):
        s = str(s)
    data = icq_encode(s)
    pkt_int(pkt, len(data), 1)
    pkt_add_arr_buf(pkt, data)


def pkt_wstr(pkt: RawPkt, s: str) -> None:
    if not s:
        pkt_int(pkt, 0, 2)
        return
    data = s.encode("utf-8", errors="replace")
    pkt_int(pkt, len(data), 2)
    pkt_add_arr_buf(pkt, data)


def pkt_dwstr(pkt: RawPkt, s: str) -> None:
    data = icq_encode(s)
    pkt_lint(pkt, len(data), 4)
    pkt_add_arr_buf(pkt, data)


def pkt_lnts(pkt: RawPkt, s: str, encoding: str = ICQ_MESSAGE_ENCODING) -> None:
    if not s:
        pkt_int(pkt, 0, 2)
        return
    data = icq_encode(s, encoding)
    pkt_lint(pkt, len(data) + 1, 2)
    pkt_add_arr_buf(pkt, data)
    pkt_int(pkt, 0, 1)


def pkt_llnts(pkt: RawPkt, s: str) -> None:
    if not s:
        pkt_int(pkt, 0, 2)
        return
    data = icq_encode(s)
    pkt_lint(pkt, len(data) + 3, 2)
    pkt_lnts(pkt, s)


def pkt_tlv_int(pkt: RawPkt, t: int, length: int, value: int) -> None:
    pkt_int(pkt, t, 2)
    pkt_int(pkt, length, 2)
    pkt_int(pkt, value, length)


def pkt_tlv_str(pkt: RawPkt, t: int, value: str) -> None:
    data = icq_encode(value)
    pkt_int(pkt, t, 2)
    pkt_int(pkt, len(data), 2)
    pkt_add_arr_buf(pkt, data)


def pkt_tlv_buf(pkt: RawPkt, t: int, data: bytes) -> None:
    pkt_int(pkt, t, 2)
    pkt_int(pkt, len(data), 2)
    pkt_add_arr_buf(pkt, data)


def pkt_init(pkt: RawPkt, channel: int, seq: List[int]) -> None:
    pkt.clear()
    pkt_int(pkt, 0x2A, 1)
    pkt_int(pkt, channel, 1)
    pkt_int(pkt, seq[0], 2)
    seq[0] = (seq[0] + 1) & 0xFFFF
    pkt_int(pkt, 0, 2)


def pkt_init_raw(pkt: RawPkt) -> None:
    pkt.clear()


def pkt_final(pkt: RawPkt) -> None:
    data_len = len(pkt.buf) - TFLAPSZ
    pkt.buf[4:6] = struct.pack(">H", data_len & 0xFFFF)


def pkt_snac(pkt: RawPkt, family: int, sub_type: int, req_id: int, flags: int = 0) -> None:
    pkt_int(pkt, family, 2)
    pkt_int(pkt, sub_type, 2)
    pkt_int(pkt, flags, 2)
    pkt_int(pkt, req_id, 4)


def get_int(pkt: RawPkt, size: int) -> int:
    if size <= 0 or pkt.pos + size > len(pkt.buf):
        return 0
    value = int.from_bytes(pkt.buf[pkt.pos : pkt.pos + size], "big")
    pkt.pos += size
    return value


def get_lint(pkt: RawPkt, size: int) -> int:
    if size <= 0 or pkt.pos + size > len(pkt.buf):
        return 0
    value = int.from_bytes(pkt.buf[pkt.pos : pkt.pos + size], "little")
    pkt.pos += size
    return value


def get_bytes(pkt: RawPkt, length: int) -> bytes:
    if length <= 0 or pkt.pos + length > len(pkt.buf):
        return b""
    data = bytes(pkt.buf[pkt.pos : pkt.pos + length])
    pkt.pos += length
    return data


def get_str(pkt: RawPkt, length: int, encoding: str = ICQ_MESSAGE_ENCODING) -> str:
    return icq_decode(get_bytes(pkt, length), encoding)


def get_tlv_str(pkt: RawPkt) -> Tuple[int, str]:
    t = get_int(pkt, 2)
    size = get_int(pkt, 2)
    return t, get_str(pkt, size)


def get_tlv_int(pkt: RawPkt) -> Tuple[int, int]:
    t = get_int(pkt, 2)
    size = get_int(pkt, 2)
    return t, get_int(pkt, size)


def get_snac(pkt: RawPkt) -> SnacHdr:
    family = get_int(pkt, 2)
    sub_type = get_int(pkt, 2)
    flags = get_int(pkt, 2)
    req_id = get_int(pkt, 4)
    return SnacHdr(family, sub_type, flags, req_id)


def get_lstr(pkt: RawPkt) -> str:
    return get_str(pkt, get_int(pkt, 1))


def get_wstr(pkt: RawPkt) -> str:
    return get_bytes(pkt, get_int(pkt, 2)).decode("utf-8", errors="replace")


def get_dwstr(pkt: RawPkt) -> str:
    return get_str(pkt, get_lint(pkt, 4))


def get_lnts(pkt: RawPkt) -> str:
    length = get_lint(pkt, 2)
    if length <= 1:
        return ""
    s = get_str(pkt, length - 1)
    pkt.pos += 1
    return s


def _meta_string_field(lpkt: RawPkt, key: int, value: str) -> None:
    pkt_int(lpkt, key, 2)
    data = icq_encode(value)
    pkt_lint(lpkt, len(data) + 3, 2)
    pkt_lint(lpkt, len(data) + 1, 2)
    pkt_add_arr_buf(lpkt, data)
    pkt_int(lpkt, 0, 1)


def create_cli_ident(pkt: RawPkt, uin: int, password: str, seq: List[int]) -> None:
    enc_pass = icq_encrypt_pass_str(password)
    pkt_init(pkt, 1, seq)
    pkt_int(pkt, 1, 4)
    pkt_tlv_str(pkt, 1, str(uin))
    pkt_tlv_buf(pkt, 2, enc_pass)
    pkt_tlv_str(pkt, 3, "ICQBasic")
    pkt_int(pkt, 0x00160002, 4)
    pkt_int(pkt, 0x010A, 2)
    pkt_int(pkt, 0x00170002, 4)
    pkt_int(pkt, 0x0014, 2)
    pkt_int(pkt, 0x00180002, 4)
    pkt_int(pkt, 0x0034, 2)
    pkt_int(pkt, 0x00190002, 4)
    pkt_int(pkt, 0x0000, 2)
    pkt_int(pkt, 0x001A0002, 4)
    pkt_int(pkt, 0x0BB8, 2)
    pkt_int(pkt, 0x00140004, 4)
    pkt_int(pkt, 0x0000043D, 4)
    pkt_tlv_str(pkt, 0x000F, "en")
    pkt_tlv_str(pkt, 0x000E, "us")
    pkt_final(pkt)


def create_cli_cookie(pkt: RawPkt, cookie: str, seq: List[int]) -> None:
    pkt_init(pkt, 1, seq)
    pkt_int(pkt, 1, 4)
    pkt_tlv_str(pkt, 6, cookie)
    pkt_final(pkt)


def create_cli_families(pkt: RawPkt, seq: List[int]) -> None:
    pairs = (
        0x00010003, 0x00130002, 0x00020001, 0x00030001, 0x00150001,
        0x00040001, 0x00060001, 0x00090001, 0x000A0001, 0x000B0001,
    )
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x17, 0, 0)
    for p in pairs:
        pkt_int(pkt, p, 4)
    pkt_final(pkt)


def create_cli_ratesrequest(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x06, 0, 0)
    pkt_final(pkt)


def create_cli_ackrates(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x08, 0, 0)
    for g in (1, 2, 3, 4, 5):
        pkt_int(pkt, g, 2)
    pkt_final(pkt)


def create_cli_reqinfo(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x0E, 0, 0)
    pkt_final(pkt)


def create_cli_reqlocation(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x02, 0x02, 0, 0)
    pkt_final(pkt)


def create_cli_reqbuddy(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x03, 0x02, 0, 0)
    pkt_final(pkt)


def create_cli_reqicbm(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x04, 0x04, 0, 0)
    pkt_final(pkt)


def create_cli_reqbos(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x09, 0x02, 0, 0)
    pkt_final(pkt)


def create_cli_setuserinfo(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x02, 0x04, 0, 0)
    pkt_tlv_buf(pkt, 5, CAPS_SETUSERINFO)
    pkt_final(pkt)


def create_cli_seticbm(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x04, 0x02, 0, 0)
    pkt_int(pkt, 0, 4)
    pkt_int(pkt, 0x0003, 2)
    pkt_int(pkt, 0x1F40, 2)
    pkt_int(pkt, 0x03E7, 2)
    pkt_int(pkt, 0x03E7, 2)
    pkt_int(pkt, 0, 4)
    pkt_final(pkt)


def create_cli_setstatus(pkt: RawPkt, status: int, ip: int, port: int, cookie: int, proxy_type: ProxyType, seq: List[int]) -> None:
    lpkt = RawPkt()
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x1E, 0, 0)
    pkt_tlv_int(pkt, 0x06, 4, status)
    pkt_tlv_int(pkt, 0x08, 2, 0)
    pkt_int(lpkt, ip, 4)
    pkt_int(lpkt, port, 4)
    proxy_code = {ProxyType.P_NONE: 0x04, ProxyType.P_SOCKS4: 0x02, ProxyType.P_SOCKS5: 0x02, ProxyType.P_HTTPS: 0x01}.get(proxy_type, 0x04)
    pkt_int(lpkt, proxy_code, 1)
    pkt_int(lpkt, ICQ_PROTOCOL_VER, 2)
    pkt_int(lpkt, cookie, 4)
    pkt_int(lpkt, 0, 2)
    pkt_int(lpkt, 0x0050, 2)
    pkt_int(lpkt, 0, 2)
    pkt_int(lpkt, 0x0003, 2)
    pkt_int(lpkt, 0, 4)
    pkt_int(lpkt, 0, 4)
    pkt_int(lpkt, 0, 4)
    pkt_int(lpkt, 0, 2)
    pkt_tlv_buf(pkt, 0x0C, lpkt.bytes())
    pkt_final(pkt)


def create_cli_setstatus_short(pkt: RawPkt, status: int, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x1E, 0, 0)
    pkt_tlv_int(pkt, 0x06, 4, status)
    pkt_final(pkt)


def create_cli_setidletime(pkt: RawPkt, is_idle: bool, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x11, 0, 0)
    pkt_int(pkt, 0x0000003C if is_idle else 0, 4)
    pkt_final(pkt)


def create_cli_ready(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x01, 0x02, 0, 0)
    pkt_add_arr_buf(pkt, CLI_READY_BUF)
    pkt_final(pkt)


def create_cli_toicqsrv(pkt: RawPkt, uin: int, command: int, data: bytes, seq: List[int], seq2: List[int], inner_seq: Optional[int] = None) -> None:
    inner = RawPkt()
    pkt_lint(inner, uin, 4)
    pkt_lint(inner, command, 2)
    pkt_lint(inner, inner_seq if inner_seq is not None else seq2[0], 2)
    if data:
        pkt_add_arr_buf(inner, data)
    body = struct.pack("<H", len(inner.buf)) + inner.bytes()
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x15, 0x02, 0, 0)
    pkt_tlv_buf(pkt, 1, body)
    pkt_final(pkt)
    seq2[0] = (seq2[0] + 1) & 0xFFFF


def create_cli_addcontact(pkt: RawPkt, uin: str, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x03, 0x04, 0, 0)
    pkt_lstr(pkt, uin)
    pkt_final(pkt)


def create_cli_addcontact_multi(pkt: RawPkt, uins: Sequence[int], seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x03, 0x04, 0, 0)
    for u in uins:
        pkt_lstr(pkt, str(u))
    pkt_final(pkt)


def create_cli_removecontact(pkt: RawPkt, uin: int, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x03, 0x05, 0, 0)
    pkt_lstr(pkt, str(uin))
    pkt_final(pkt)


def create_cli_addvisible(pkt: RawPkt, uins: Sequence[str], seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x09, 0x05, 0, 0)
    for u in uins:
        pkt_lstr(pkt, u)
    pkt_final(pkt)


def create_cli_remvisible(pkt: RawPkt, uin: int, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x09, 0x06, 0, 0)
    pkt_lstr(pkt, str(uin))
    pkt_final(pkt)


def create_cli_addinvisible(pkt: RawPkt, uins: Sequence[str], seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x09, 0x07, 0, 0)
    for u in uins:
        pkt_lstr(pkt, u)
    pkt_final(pkt)


def create_cli_reminvisible(pkt: RawPkt, uin: int, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x09, 0x08, 0, 0)
    pkt_lstr(pkt, str(uin))
    pkt_final(pkt)


def create_cli_ackofflinemsgs(pkt: RawPkt, uin: int, seq: List[int], seq2: List[int]) -> None:
    create_cli_toicqsrv(pkt, uin, CMD_ACKOFFMSG, b"", seq, seq2)


def create_cli_sendmsg(pkt: RawPkt, i_time: int, i_random: int, uin: str, msg: str, seq: List[int]) -> None:
    lpkt = RawPkt()
    pmsg = RawPkt()
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x04, 0x06, 0, 0)
    pkt_int(pkt, i_time, 4)
    pkt_int(pkt, i_random, 4)
    pkt_int(pkt, 1, 2)
    pkt_lstr(pkt, uin)
    pkt_tlv_int(lpkt, 1281, 1, 1)
    pkt_int(pmsg, 0, 4)
    pkt_str(pmsg, msg)
    pkt_tlv_buf(lpkt, 257, pmsg.bytes())
    pkt_tlv_buf(pkt, 2, lpkt.bytes())
    pkt_tlv_int(pkt, 6, 0, 0)
    pkt_final(pkt)


def create_cli_sendurl(pkt: RawPkt, i_time: int, i_random: int, my_uin: int, uin: int, url: str, description: str, seq: List[int]) -> None:
    lpkt = RawPkt()
    s = description + "\xfe" + url
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x04, 0x06, 0, 0)
    pkt_int(pkt, i_time, 4)
    pkt_int(pkt, i_random, 4)
    pkt_int(pkt, 4, 2)
    pkt_lstr(pkt, str(uin))
    pkt_lint(lpkt, my_uin, 4)
    pkt_int(lpkt, 4, 1)
    pkt_int(lpkt, 0, 1)
    pkt_lnts(lpkt, s)
    pkt_tlv_buf(pkt, 5, lpkt.bytes())
    pkt_tlv_int(pkt, 6, 0, 0)
    pkt_final(pkt)


def create_cli_authorize(pkt: RawPkt, uin: str, auth: int, reason: str, seq: List[int]) -> None:
    if auth == 1:
        reason = ""
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x13, 0x1A, 0x1A, 0)
    pkt_lstr(pkt, uin)
    pkt_int(pkt, auth, 1)
    pkt_int(pkt, len(reason), 2)
    pkt_str(pkt, reason)
    pkt_int(pkt, 0, 2)
    pkt_final(pkt)


def create_cli_hello(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 1, seq)
    pkt_int(pkt, 1, 4)
    pkt_final(pkt)


def create_cli_goodbye(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 1, seq)
    pkt_final(pkt)


def create_cli_keepalive(pkt: RawPkt, seq: List[int]) -> None:
    pkt_init(pkt, 5, seq)
    pkt_final(pkt)


def create_cli_reqauth(pkt: RawPkt, uin: str, msg: str, seq: List[int]) -> None:
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x13, 0x18, 0x18, 0)
    pkt_lstr(pkt, uin)
    pkt_wstr(pkt, msg)
    pkt_int(pkt, 0, 2)
    pkt_final(pkt)


def create_cli_sendadvmsg_custom(
    pkt: RawPkt,
    status: int,
    ff_seq: int,
    i_time: int,
    i_random: int,
    uin: int,
    cmd: int,
    msg_type: int,
    acmd: int,
    msg: str,
    extra: bytes,
    rtf_format: bool,
    seq: List[int],
) -> None:
    i_time = int(time.time() * 1000) & 0xFFFFFFFF
    lp2711 = RawPkt()
    lp05 = RawPkt()
    pkt_init(pkt, 2, seq)
    pkt_snac(pkt, 0x04, 0x06, 0, 0)
    pkt_lint(pkt, i_time, 4)
    pkt_int(pkt, i_random, 2)
    pkt_int(pkt, 2, 4)
    pkt_lstr(pkt, str(uin))
    pkt_int(lp2711, 0x1B, 1)
    pkt_int(lp2711, ICQ_PROTOCOL_VER, 2)
    pkt_int(lp2711, 0, 1)
    for _ in range(4):
        pkt_int(lp2711, 0, 4)
    pkt_int(lp2711, 0, 2)
    pkt_int(lp2711, 0x03, 1)
    pkt_int(lp2711, 0, 4)
    pkt_int(lp2711, ff_seq, 2)
    pkt_int(lp2711, 0x0E00, 2)
    pkt_int(lp2711, ff_seq, 2)
    for _ in range(3):
        pkt_int(lp2711, 0, 4)
    pkt_int(lp2711, cmd, 1)
    pkt_int(lp2711, msg_type, 1)
    pkt_lint(lp2711, status_to_int(status) & 0xFFFF, 2)
    pkt_int(lp2711, 0x0100 if msg_type == 0x03 else 0, 2)
    if not msg:
        pkt_lint(lp2711, 1, 2)
        pkt_int(lp2711, 0, 1)
    else:
        pkt_lnts(lp2711, msg)
    if cmd == 0x01:
        pkt_int(lp2711, 0, 4)
        pkt_int(lp2711, 0xFFFFFF00, 4)
    elif extra:
        pkt_add_arr_buf(lp2711, extra)
    if rtf_format:
        pkt_lint(lp2711, len(MSG_GUID), 4)
        pkt_str(lp2711, MSG_GUID)
    pkt_int(lp05, 0, 2)
    pkt_int(lp05, i_time, 4)
    pkt_int(lp05, i_random, 2)
    pkt_int(lp05, 0, 2)
    pkt_add_arr_buf(lp05, CAPABILITIES_MSG)
    pkt_tlv_int(lp05, 0x000A, 2, acmd)
    pkt_tlv_int(lp05, 0x000F, 0, 0)
    pkt_tlv_buf(lp05, 0x2711, lp2711.bytes())
    pkt_tlv_buf(pkt, 5, lp05.bytes())
    pkt_tlv_int(pkt, 3, 0, 0)
    pkt_final(pkt)


def create_cli_sendmsg_advanced(pkt: RawPkt, status: int, i_time: int, i_random: int, uin: int, msg: str, rtf_format: bool, seq: List[int]) -> None:
    create_cli_sendadvmsg_custom(pkt, status, 0xFFFF, i_time, i_random, uin, 0x01, 0x00, 0x0001, msg, b"", rtf_format, seq)


def create_cli_metareqinfo(pkt: RawPkt, uin: int, dest_uin: int, seq: List[int], seq2: List[int]) -> None:
    lpkt = RawPkt()
    pkt_lint(lpkt, 0x04B2, 2)
    pkt_lint(lpkt, dest_uin, 4)
    create_cli_toicqsrv(pkt, uin, CMD_REQINFO, lpkt.bytes(), seq, seq2)


def create_cli_metareqinfo_short(pkt: RawPkt, uin: int, dest_uin: int, seq: List[int], seq2: List[int]) -> None:
    lpkt = RawPkt()
    pkt_int(lpkt, 0xBA04, 2)
    pkt_lint(lpkt, dest_uin, 4)
    create_cli_toicqsrv(pkt, uin, CMD_REQINFO, lpkt.bytes(), seq, seq2)


def create_cli_searchbyuin(pkt: RawPkt, uin: int, dest_uin: int, seq: List[int], seq2: List[int]) -> None:
    lpkt = RawPkt()
    pkt_int(lpkt, 0x6905, 2)
    pkt_int(lpkt, 0x3601, 2)
    pkt_int(lpkt, 0x0400, 2)
    pkt_lint(lpkt, dest_uin, 4)
    create_cli_toicqsrv(pkt, uin, CMD_REQINFO, lpkt.bytes(), seq, seq2)


def create_cli_searchbymail(pkt: RawPkt, uin: int, email: str, seq: List[int], seq2: List[int]) -> None:
    lpkt = RawPkt()
    pkt_int(lpkt, 0x7305, 2)
    pkt_int(lpkt, 0x5E01, 2)
    pkt_llnts(lpkt, email)
    create_cli_toicqsrv(pkt, uin, CMD_REQINFO, lpkt.bytes(), seq, seq2)


class ICQNet:
    def __init__(self) -> None:
        self.host = ""
        self.port = "5190"
        self.proxy_type = ProxyType.P_NONE
        self.proxy_host = ""
        self.proxy_port = ""
        self.proxy_user = ""
        self.proxy_pass = ""
        self.proxy_auth = False
        self.proxy_resolve = False
        self.on_error: Optional[Callable[..., None]] = None
        self.on_handle_pkt: Optional[Callable[[FlapHdr, bytes], None]] = None
        self.on_disconnect: Optional[Callable[[], None]] = None
        self.on_connect_error: Optional[Callable[[int, str], None]] = None
        self.on_pkt_parse: Optional[Callable[[bytes, bool], None]] = None
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._src = bytearray()
        self._new_flap: Optional[FlapHdr] = None
        self._flap_set = False

    def connect(self) -> None:
        self.disconnect(wait=False, notify=False)
        self._stop.clear()
        self._src.clear()
        self._flap_set = False
        if self.proxy_type != ProxyType.P_NONE:
            raise NotImplementedError("Proxy connections are not implemented in this port")
        sock = socket.create_connection((self.host, int(self.port)), timeout=30)
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def disconnect(self, wait: bool = True, notify: bool = True) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if wait and self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        if notify and self.on_disconnect:
            self.on_disconnect()

    def send_data(self, data: bytes) -> None:
        if not self._sock:
            return
        if self.on_pkt_parse:
            self.on_pkt_parse(data, False)
        self._sock.sendall(data)

    def _reader(self) -> None:
        assert self._sock is not None
        try:
            while not self._stop.is_set():
                try:
                    chunk = self._sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not self._stop.is_set() and self.on_connect_error:
                        self.on_connect_error(0, str(exc))
                    break
                if not chunk:
                    break
                self._handle_flap_data(chunk)
        except Exception as exc:
            if not self._stop.is_set() and self.on_connect_error:
                self.on_connect_error(0, str(exc))
        if not self._stop.is_set() and self.on_disconnect:
            self.on_disconnect()

    def _handle_flap_data(self, buffer: bytes) -> None:
        for b in buffer:
            self._src.append(b)
            if len(self._src) >= TFLAPSZ and not self._flap_set:
                self._flap_set = True
                self._new_flap = FlapHdr(
                    ident=self._src[0],
                    ch_id=self._src[1],
                    seq=struct.unpack(">H", self._src[2:4])[0],
                    data_len=struct.unpack(">H", self._src[4:6])[0],
                )
                if self._new_flap.data_len > 8192:
                    if self.on_error:
                        self.on_error(ErrorType.ERR_PROTOCOL, "Malformed packet length", 0)
                    self.disconnect()
                    return
            if self._new_flap and len(self._src) == self._new_flap.data_len + TFLAPSZ:
                flap = self._new_flap
                payload = bytes(self._src[TFLAPSZ:])
                if self.on_pkt_parse:
                    self.on_pkt_parse(bytes(self._src), True)
                self._src.clear()
                self._new_flap = None
                self._flap_set = False
                if flap.ident != 0x2A:
                    if self.on_error:
                        self.on_error(ErrorType.ERR_PROTOCOL, "Malformed FLAP ident", 0)
                    self.disconnect()
                    return
                if self.on_handle_pkt:
                    self.on_handle_pkt(flap, payload)


class ICQClient:
    def __init__(self) -> None:
        self.sock = ICQNet()
        self.uin = 0
        self.password = ""
        self.icq_server = "kicq.ru"
        self.icq_port = "5190"
        self.proxy_type = ProxyType.P_NONE
        self.proxy_host = ""
        self.proxy_port = ""
        self.proxy_user = ""
        self.proxy_pass = ""
        self.proxy_auth = False
        self.proxy_resolve = False
        self.convert_to_plaintext = True
        self.message_encoding = ICQ_MESSAGE_ENCODING
        self.auto_away_message = ""
        self.connection_timeout = 0
        self.disable_direct_connections = False
        self.search_seq = 0
        self.last_error = ""
        self.status = S_ONLINE
        self.logged_in = False
        self.contact_list: List[str] = []
        self.visible_list: List[str] = []
        self.invisible_list: List[str] = []
        self._seq = [random.randint(0, 0xAAAA)]
        self._seq2 = [2]
        self._cookie = ""
        self._first_connect = True
        self._registering = False
        self._reg_password = ""
        self._dconn_cookie = 0
        self._info_chain: Dict[str, str] = {}
        self._sinfo_chain: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._login_event = threading.Event()
        self._login_ok = False

        self.on_login: Optional[Callable[["ICQClient"], None]] = None
        self.on_logoff: Optional[Callable[["ICQClient"], None]] = None
        self.on_message_recv: Optional[Callable[["ICQClient", str, str], None]] = None
        self.on_url_recv: Optional[Callable[["ICQClient", str, str, str], None]] = None
        self.on_offline_msg_recv: Optional[Callable[["ICQClient", datetime, str, str], None]] = None
        self.on_status_change: Optional[Callable[["ICQClient", str, int], None]] = None
        self.on_user_offline: Optional[Callable[["ICQClient", str], None]] = None
        self.on_added_you: Optional[Callable[["ICQClient", str], None]] = None
        self.on_user_found: Optional[Callable[..., None]] = None
        self.on_user_not_found: Optional[Callable[["ICQClient"], None]] = None
        self.on_error: Optional[Callable[["ICQClient", ErrorType, str, int], None]] = None
        self.on_connection_failed: Optional[Callable[["ICQClient", int, str], None]] = None
        self.on_auth_request: Optional[Callable[["ICQClient", str, str], None]] = None
        self.on_auth_response: Optional[Callable[["ICQClient", str, bool, str], None]] = None
        self.on_msg_ack: Optional[Callable[["ICQClient", str, int], None]] = None
        self.on_contact_list_recv: Optional[Callable[["ICQClient", str, List[str]], None]] = None
        self.on_auto_msg_response: Optional[Callable[["ICQClient", str, int, int, str], None]] = None
        self.on_user_general_info: Optional[Callable[..., None]] = None
        self.on_user_info_more: Optional[Callable[..., None]] = None
        self.on_user_info_about: Optional[Callable[["ICQClient", str, str], None]] = None
        self.on_icbm_error: Optional[Callable[["ICQClient", int], None]] = None
        self.on_pkt_parse: Optional[Callable[[bytes, bool], None]] = None

        self.sock.on_error = self._on_net_error
        self.sock.on_handle_pkt = self._handle_packet
        self.sock.on_disconnect = self._on_disconnect
        self.sock.on_connect_error = self._on_connect_error
        self.sock.on_pkt_parse = self._on_pkt_parse

    def _init_net(self) -> None:
        self.sock.host = self.icq_server
        self.sock.port = self.icq_port
        self.sock.proxy_type = self.proxy_type
        self.sock.proxy_host = self.proxy_host
        self.sock.proxy_port = self.proxy_port
        self.sock.proxy_user = self.proxy_user
        self.sock.proxy_pass = self.proxy_pass
        self.sock.proxy_auth = self.proxy_auth
        self.sock.proxy_resolve = self.proxy_resolve

    def _on_net_error(self, error_type: ErrorType, msg: str, add_type: int) -> None:
        self._emit_error(error_type, msg, add_type)

    def _emit_error(self, error_type: ErrorType, msg: str, add_type: int = 0) -> None:
        self.last_error = msg
        if self.on_error:
            self.on_error(self, error_type, msg, add_type)

    def _on_disconnect(self) -> None:
        with self._lock:
            self.logged_in = False

    def _on_connect_error(self, code: int, msg: str) -> None:
        if self.on_connection_failed:
            self.on_connection_failed(self, code, msg)

    def _on_pkt_parse(self, data: bytes, incoming: bool) -> None:
        if self.on_pkt_parse:
            self.on_pkt_parse(data, incoming)

    def _send(self, pkt: RawPkt) -> None:
        self.sock.send_data(pkt.bytes())

    def login(self, status: int = S_ONLINE, birthday: bool = False) -> None:
        self._seq2[0] = 2
        self._cookie = ""
        self._first_connect = True
        self.status = status | SF_BIRTH if birthday else status
        self.logged_in = False
        self._registering = False
        self._login_event.clear()
        self._login_ok = False
        self._init_net()
        self.sock.connect()

    def wait_login(self, timeout: float = 60.0) -> bool:
        return self._login_event.wait(timeout) and self._login_ok

    def logoff(self) -> None:
        pkt = RawPkt()
        create_cli_goodbye(pkt, self._seq)
        self._send(pkt)
        time.sleep(0.01)
        self.disconnect()
        if self.on_logoff:
            self.on_logoff(self)

    def disconnect(self) -> None:
        self.sock.disconnect()

    def send_message(self, uin: Union[str, int], msg: str) -> None:
        if not self.logged_in:
            return
        self.send_message_advanced(int(str(uin)), msg)

    def send_url(self, uin: int, url: str, description: str) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_sendurl(pkt, 0, random.randint(0, 0xFFFFAA), self.uin, uin, url, description, self._seq)
        self._send(pkt)

    def add_contact(self, uin: int) -> bool:
        s = str(uin)
        if s not in self.contact_list:
            self.contact_list.append(s)
        else:
            return False
        if not self.logged_in:
            return True
        pkt = RawPkt()
        create_cli_addcontact(pkt, s, self._seq)
        self._send(pkt)
        return True

    def add_contact_multi(self, uins: Sequence[int]) -> bool:
        for u in uins:
            s = str(u)
            if s not in self.contact_list:
                self.contact_list.append(s)
        if not self.logged_in:
            return True
        pkt = RawPkt()
        create_cli_addcontact_multi(pkt, uins, self._seq)
        self._send(pkt)
        return True

    def remove_contact(self, uin: int) -> None:
        s = str(uin)
        if s in self.contact_list:
            self.contact_list.remove(s)
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_removecontact(pkt, uin, self._seq)
        self._send(pkt)

    def send_auth_request(self, uin: str, msg: str) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_reqauth(pkt, uin, msg, self._seq)
        self._send(pkt)

    def send_auth_response(self, uin: str, authorize: bool, reason: str = "") -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_authorize(pkt, uin, 1 if authorize else 0, reason, self._seq)
        self._send(pkt)

    def send_keep_alive(self) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_keepalive(pkt, self._seq)
        self._send(pkt)

    def request_offline_messages(self) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_toicqsrv(pkt, self.uin, CMD_REQOFFMSG, b"", self._seq, self._seq2)

    def request_info(self, uin: int) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_metareqinfo(pkt, self.uin, uin, self._seq, self._seq2)

    def request_info_short(self, uin: int) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_metareqinfo_short(pkt, self.uin, uin, self._seq, self._seq2)

    def search_by_uin(self, uin: int) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_searchbyuin(pkt, self.uin, uin, self._seq, self._seq2)

    def search_by_mail(self, email: str) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        create_cli_searchbymail(pkt, self.uin, email, self._seq, self._seq2)

    def set_status(self, new_status: int) -> None:
        if not self.logged_in:
            return
        if status_to_int(self.status) == status_to_int(new_status):
            return
        pkt = RawPkt()
        create_cli_setstatus_short(pkt, new_status, self._seq)
        self._send(pkt)
        self.status = new_status

    def add_contact_visible(self, uin: int) -> bool:
        s = str(uin)
        if s in self.visible_list:
            return False
        self.visible_list.append(s)
        if self.logged_in and status_to_int(self.status) == S_INVISIBLE:
            pkt = RawPkt()
            create_cli_addvisible(pkt, [s], self._seq)
            self._send(pkt)
        return True

    def add_contact_invisible(self, uin: int) -> bool:
        s = str(uin)
        if s in self.invisible_list:
            return False
        self.invisible_list.append(s)
        if self.logged_in and status_to_int(self.status) != S_INVISIBLE:
            pkt = RawPkt()
            create_cli_addinvisible(pkt, [s], self._seq)
            self._send(pkt)
        return True

    def remove_contact_visible(self, uin: int) -> None:
        s = str(uin)
        if s in self.visible_list:
            self.visible_list.remove(s)
        if self.logged_in:
            pkt = RawPkt()
            create_cli_remvisible(pkt, uin, self._seq)
            self._send(pkt)

    def remove_contact_invisible(self, uin: int) -> None:
        s = str(uin)
        if s in self.invisible_list:
            self.invisible_list.remove(s)
        if self.logged_in:
            pkt = RawPkt()
            create_cli_reminvisible(pkt, uin, self._seq)
            self._send(pkt)

    def send_message_advanced(self, uin: int, msg: str, msg_id: int = 0, rtf_format: bool = False) -> None:
        if not self.logged_in:
            return
        pkt = RawPkt()
        rid = msg_id if msg_id else random.randint(0, 0xFFFF)
        create_cli_sendmsg_advanced(pkt, self.status, 0, rid, uin, msg, rtf_format, self._seq)
        self._send(pkt)

    def register_new_uin(self, password: str) -> None:
        self._registering = True
        self._reg_password = password
        self.logged_in = False
        self._init_net()
        self.sock.connect()

    def change_password(self, new_password: str) -> None:
        if not self.logged_in:
            return
        lpkt = RawPkt()
        pkt_int(lpkt, 0x2E04, 2)
        pkt_lnts(lpkt, new_password)
        pkt = RawPkt()
        create_cli_toicqsrv(pkt, self.uin, CMD_REQINFO, lpkt.bytes(), self._seq, self._seq2)
        self._send(pkt)

    def _handle_packet(self, flap: FlapHdr, data: bytes) -> None:
        with self._lock:
            if flap.ch_id == 1:
                if flap.data_len == 4:
                    if self._registering:
                        pkt = RawPkt()
                        create_cli_hello(pkt, self._seq)
                        self._send(pkt)
                        return
                    if self._first_connect:
                        pkt = RawPkt()
                        create_cli_ident(pkt, self.uin, self.password, self._seq)
                        self._send(pkt)
                    else:
                        pkt = RawPkt()
                        create_cli_cookie(pkt, self._cookie, self._seq)
                        self._send(pkt)
                self._first_connect = False
                return

            if flap.ch_id == 2:
                pkt = RawPkt()
                pkt.buf = bytearray(data)
                pkt.reset_read()
                snac = get_snac(pkt)
                if snac.family == 0x01:
                    if snac.sub_type == 0x03:
                        p = RawPkt()
                        create_cli_families(p, self._seq)
                        self._send(p)
                    elif snac.sub_type == 0x07:
                        p = RawPkt()
                        create_cli_ackrates(p, self._seq)
                        self._send(p)
                        for fn in (
                            create_cli_seticbm,
                            create_cli_reqinfo,
                            create_cli_reqlocation,
                            create_cli_reqbuddy,
                            create_cli_reqicbm,
                            create_cli_reqbos,
                        ):
                            p = RawPkt()
                            fn(p, self._seq)
                            self._send(p)
                    elif snac.sub_type == 0x13:
                        p = RawPkt()
                        create_cli_ratesrequest(p, self._seq)
                        self._send(p)
                elif snac.family == 0x03:
                    if snac.sub_type == 0x0B:
                        self._handle_user_online(pkt)
                    elif snac.sub_type == 0x0C:
                        u = get_str(pkt, get_int(pkt, 1))
                        if self.on_user_offline:
                            self.on_user_offline(self, u)
                elif snac.family == 0x04:
                    if snac.sub_type == 0x01:
                        err = get_int(pkt, 2)
                        if self.on_icbm_error:
                            self.on_icbm_error(self, err)
                    elif snac.sub_type == 0x07:
                        self._handle_incoming_message(pkt)
                    elif snac.sub_type in (0x0B, 0x0C):
                        u = get_lstr(pkt)
                        msg_id = get_int(pkt, 2)
                        if self.on_msg_ack:
                            self.on_msg_ack(self, u, msg_id)
                elif snac.family == 0x09 and snac.sub_type == 0x03:
                    p = RawPkt()
                    create_cli_setuserinfo(p, self._seq)
                    self._send(p)
                    if self.contact_list:
                        uins = [int(x) for x in self.contact_list]
                        p = RawPkt()
                        create_cli_addcontact_multi(p, uins, self._seq)
                        self._send(p)
                    if status_to_int(self.status) != S_INVISIBLE:
                        p = RawPkt()
                        create_cli_addinvisible(p, self.invisible_list, self._seq)
                        self._send(p)
                    else:
                        p = RawPkt()
                        create_cli_addvisible(p, self.visible_list, self._seq)
                        self._send(p)
                    p = RawPkt()
                    create_cli_setidletime(p, status_to_int(self.status) in (S_AWAY, S_NA), self._seq)
                    self._send(p)
                    self._dconn_cookie = random.randint(0, 0x7FFFFFFF)
                    p = RawPkt()
                    create_cli_setstatus(p, self.status, 0, 0, self._dconn_cookie, self.proxy_type, self._seq)
                    self._send(p)
                    p = RawPkt()
                    create_cli_ready(p, self._seq)
                    self._send(p)
                    self.logged_in = True
                    self._login_ok = True
                    self._login_event.set()
                    if self.on_login:
                        self.on_login(self)
                elif snac.family == 0x13:
                    if snac.sub_type == 0x19:
                        u = get_lstr(pkt)
                        reason = get_wstr(pkt)
                        if self.on_auth_request:
                            self.on_auth_request(self, u, reason)
                    elif snac.sub_type == 0x1C:
                        u = get_lstr(pkt)
                        if self.on_added_you:
                            self.on_added_you(self, u)
                elif snac.family == 0x15 and snac.sub_type == 0x03:
                    self._handle_from_icqsrv(pkt)
                return

            if flap.ch_id == 4:
                if self.logged_in or self._registering:
                    self._on_connect_error(1, "error icq login")
                    self.disconnect()
                    return
                pkt = RawPkt()
                pkt.buf = bytearray(data)
                pkt.reset_read()
                t, _ = get_tlv_str(pkt)
                if t != 1:
                    self._emit_error(ErrorType.ERR_PROTOCOL, "Malformed login packet", 0)
                    self.disconnect()
                    return
                t, hostport = get_tlv_str(pkt)
                if "MISMATCH_PASSWD" in hostport:
                    self._emit_error(ErrorType.ERR_LOGIN, "Bad password", 0)
                    self._login_event.set()
                    return
                if t != 5:
                    self._emit_error(ErrorType.ERR_PROTOCOL, "Malformed login packet", 0)
                    self.disconnect()
                    return
                t, self._cookie = get_tlv_str(pkt)
                if t != 6:
                    self._emit_error(ErrorType.ERR_PROTOCOL, "Malformed login packet", 0)
                    self.disconnect()
                    return
                p = RawPkt()
                pkt_init(p, 4, self._seq)
                pkt_final(p)
                self._send(p)
                self.sock.disconnect(wait=False, notify=False)
                if ":" not in hostport:
                    self._emit_error(ErrorType.ERR_PROTOCOL, "Malformed login packet", 0)
                    return
                host, port = hostport.split(":", 1)
                self.icq_server = host
                self.icq_port = port
                self._init_net()
                self.sock.connect()

    def _handle_user_online(self, pkt: RawPkt) -> None:
        uin = get_lstr(pkt)
        status = get_int(pkt, 4)
        if self.on_status_change:
            self.on_status_change(self, uin, status)

    def _handle_incoming_message(self, pkt: RawPkt) -> None:
        i_time = get_int(pkt, 4)
        i_random = get_int(pkt, 2)
        get_int(pkt, 2)
        msg_type = get_int(pkt, 2)
        if msg_type == 1:
            uin = get_str(pkt, get_int(pkt, 1))
            get_int(pkt, 2)
            count = get_int(pkt, 2)
            for _ in range(count):
                get_int(pkt, 2)
                get_int(pkt, get_int(pkt, 2))
            while True:
                t = get_int(pkt, 2)
                if t == 0:
                    break
                if t == 2:
                    get_int(pkt, 4)
                    get_int(pkt, get_int(pkt, 2))
                    get_int(pkt, 2)
                    ulen = get_int(pkt, 2) - 4
                    charset = get_int(pkt, 2)
                    get_int(pkt, 2)
                    raw = get_bytes(pkt, ulen)
                    if charset == 0x0002:
                        msg = ucs2be_to_str(raw)
                    else:
                        msg = icq_decode(raw)
                    if self.convert_to_plaintext:
                        msg = rtf2plain(msg)
                    if msg and self.on_message_recv:
                        self.on_message_recv(self, msg, uin)
                else:
                    get_int(pkt, get_int(pkt, 2))
            return

        if msg_type == 2:
            uin = get_str(pkt, get_int(pkt, 1))
            get_int(pkt, 4)
            msg = ""
            for _ in range(7):
                if get_int(pkt, 2) != 5:
                    get_int(pkt, get_int(pkt, 2))
                    continue
                fsize = get_int(pkt, 2)
                if get_int(pkt, 2) != 0:
                    pkt.pos += fsize - 2
                    continue
                pkt.pos += 16 + 8
                for _tlv in range(6):
                    tlv_type = get_int(pkt, 2)
                    if tlv_type == 0x2711:
                        get_int(pkt, 2)
                        chunk_start = pkt.pos
                        if get_int(pkt, 1) != 0x1B:
                            return
                        pkt.pos += 26
                        ff_seq = get_int(pkt, 2)
                        pkt.pos += 16
                        mtype = get_int(pkt, 1)
                        mflag = get_int(pkt, 1)
                        get_int(pkt, 4)
                        if (mtype & 0xE0) == 0xE0 and mflag == MFLAG_AUTO:
                            amsg = get_lnts(pkt)
                            if self.on_auto_msg_response:
                                self.on_auto_msg_response(self, uin, i_random, mtype, amsg)
                        else:
                            msg = get_lnts(pkt)
                        chunks = pkt.buf[chunk_start : chunk_start + 47]
                        ack = RawPkt()
                        pkt_init(ack, 2, self._seq)
                        pkt_snac(ack, 0x04, 0x0B, 0, 0)
                        pkt_add_arr_buf(ack, bytes(chunks[:10]))
                        pkt_lstr(ack, uin)
                        pkt_int(ack, 0x0003, 2)
                        pkt_add_arr_buf(ack, bytes(chunks))
                        pkt_int(ack, 0, 4)
                        if (mtype & 0xE0) == 0xE0:
                            pkt_lnts(ack, self.auto_away_message)
                        else:
                            pkt_int(ack, 1, 1)
                            pkt_int(ack, 0, 4)
                            pkt_int(ack, 0, 2)
                            pkt_int(ack, 0xFFFFFF00, 4)
                        pkt_final(ack)
                        self._send(ack)
                        if msg:
                            if self.convert_to_plaintext:
                                msg = rtf2plain(msg)
                            if mtype == M_PLAIN and self.on_message_recv:
                                self.on_message_recv(self, msg, uin)
                        return
                    else:
                        get_int(pkt, get_int(pkt, 2))
            return

        if msg_type == 4:
            uin = get_lstr(pkt)
            for _ in range(5):
                v = get_int(pkt, 1)
                if v == 5 or (get_int(pkt, 1) == 5 and v == 0):
                    if v == 5:
                        pkt.pos += 40
                    else:
                        pkt.pos += 2
                    get_lint(pkt, 4)
                    mtype = get_lint(pkt, 2)
                    msg = get_lnts(pkt)
                    if self.convert_to_plaintext:
                        msg = rtf2plain(msg)
                    if mtype == M_PLAIN and msg and self.on_message_recv:
                        self.on_message_recv(self, msg, uin)
                    return
                get_int(pkt, get_int(pkt, 2))

    def _handle_from_icqsrv(self, pkt: RawPkt) -> None:
        if get_int(pkt, 2) != 1:
            return
        pkt.pos += 8
        code = get_int(pkt, 2)
        if code == 0x4100:
            pkt.pos += 2
            uin = str(get_lint(pkt, 4))
            year = get_lint(pkt, 2)
            month = get_lint(pkt, 1)
            day = get_lint(pkt, 1)
            hour = get_lint(pkt, 1)
            minute = get_lint(pkt, 1)
            mtype = get_lint(pkt, 2)
            msg = get_lnts(pkt)
            if self.convert_to_plaintext:
                msg = rtf2plain(msg)
            dt = datetime(year, max(1, month), max(1, day), hour, minute)
            if mtype == M_PLAIN and self.on_offline_msg_recv:
                self.on_offline_msg_recv(self, dt, msg, uin)
        elif code == 0x4200:
            self._seq2[0] = 2
            p = RawPkt()
            create_cli_ackofflinemsgs(p, self.uin, self._seq, self._seq2)
            self._send(p)


__all__ = [
    "ICQClient",
    "ICQNet",
    "RawPkt",
    "ErrorType",
    "ProxyType",
    "InfoType",
    "S_ONLINE",
    "S_INVISIBLE",
    "S_AWAY",
    "M_PLAIN",
    "status_to_int",
    "status_to_str",
    "rtf2plain",
]

