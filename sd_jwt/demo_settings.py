DEFAULT_SIGNIGN_ALG = "RS256"
SD_CLAIMS_KEY = "_sd"

ISSUER = "https://example.com/issuer"

DEFAULT_KEY_SIZE = 2048
DEFAULT_KTY = "RSA"

ISSUER_KEY_DICT = {
    "d": "JQ5-MZ5wuwb8KBYiJqDbtCG3H9daEK-ITOnxWP7k7jcI4lotkO3vmMuCw_XJQKShUV6TpeI7AT_je1SY_7-ram2oM1xJcm0zoOUOvK62l7006bUB3BfHmYXEdEtr_-bzA_mMwpQsEztT_V0BNIFwX-oXnO9LXSTrgFcUTUnS_Vyp-0noziWQN4sx5YlBTniRIhAyU1eYqUDpqza2hmKJEpEYUR73h3OLUEQJblEY4-WR989MK4ff_GcJ7y1dV8YraTmsoOKs2qmelMdfO_SgZ5SjKNtl38yvr8hkEJpXgbBJV1bjzu2IOysxmxtrOjxHRjDHQEV2MAoYObJki33rzQ",
    "dp": "gDE4XKCd_TbQLH_buP3UDpgCSi3TmdaTfmiNyJHxrNqBTehsMYhEUDN2t84NEJKF-QXWaRP1IHb3T5MvDNrXZUf8vHQFh6BXcOceF2dC_PvGIX3K1Nwnb8T9u1VkwaN95h_hMoCk7E8mKw37cX4eeoRqtLsxBSFODbIhi4b9Yq0",
    "dq": "c26RA1V_1rX8sfrMMkCDADbb7tD55h8obuX2FMs2LhBs4T9vzwsm8dKZ1cl0VYui04hc-x6tAMwYFrz4Y0cGBcHQHgOL1ame_pQos1tCbOChBeczXVLlcKhwsvFCNjkM4jV05o8PHZ9Jk8dFbGJ_1RLTgaGLktFQgfkas8VjwKs",
    "e": "AQAB",
    "key_size": 2048,
    "kty": "RSA",
    "n": "6GwTTwcjVyOtKtuGf7ft5PAU0GiDtnD4DGcmtVrFQHVhtx05-DJigfmR-3Tetw-Od5su4TNZYzjh3tQ6Bj1HRdOfGmX9E9YbPw4goKg_d0kM4oZMUd64tmlAUFtX0NYaYnRkjQtok2CJBUq22wucK93JV11T38PYDATqbK9UFqMM3vu07XXlaQGXP1vh4iX04w4dU4d2xTACXho_wKKcV85yvIGrO1eGwwnSilTiqQbak31_VnHGNVVZEk4dnVO7eOc6MVZa-qPkVj77GaILO53TMq69Vp1faJoGFHjha_Ue5D8zfpiAEx2AsAeotIwNk2QT0UZkeZoK23Q-s4p1dQ",
    "p": "8_vXPiy3OtAeACYgNm6iIo5c1Cbwuh3tJ0T6lMcGEo7Rcro0nwNFISvPnFp_1Wl8I1ts6FTMsKyoTneveDrptlWSRRZNrFS_GyAQpG6GPUfqNh9n4T5J3mYw6-fLPM0hL0_EbDNiEXyL53ecMfi2xlg2T2opuZFeToogqipDudc",
    "q": "8953MqqJ7v-bc5rPQuRjqbHIxZJdEF-VsSz1lVbVEqnxV0XEUnM8yZqsXUe07V-5OEzJBqgrgLCcOeh5Jfs1MZI9tegRCwdw3uiqECAAVMtsM9xCwBY0mPu-oqOwaKsVOj2Slr1Gq-s67FdjGeMq6udjPWHgQ5QeOy78pgHtWZM",
    "qi": "FghQIPGfbjWmdwl5szDRPq1_NcGWSt9Eswu5o-JJq-jWUgTljqxufteg96k7pmBXMAQjGKn_lY41AojokVB4KWTJrPHF6z6oAm90kMLuFi80IbXzdb6TnsYHue_Y3Tbs4GtYP7YU9x2zrghsaUcDNJ7yH13h9F7GyiDkpySgcaM",
}
HOLDER_KEY_DICT = {
    "d": "kJSUdxpBVUHSSe0HfJfeO3q-iDgjXlS9zEZmgifbUPtjcT8recXwmwwRTZzhb9avNy8tyL8i1dJooAeMnudECz4u5zRY6VIXnSkO2cSPhZ-fyXPpC1BAnzf8RSn8rGu_auRrfyq3dfYw6dLt7dzA-hsUANzD63x8Tt4v9eiwsp65BlR1pvf0BIV3WMGLtgx0hTUQBUxIx0hgDG439a0gLY0T86m9LEMCcVXONNTWbScQf5KsHLWQgbjCeUc_4szy4RwsaFnF40uut_fdZyM_O1pOsfYJLa8fmN3FC72l4UdJvtFXWuH-20ywTEOKISF7CRx5BsifOnyEMTeAVEE9wQ",
    "dp": "kqCTyxU7gJa3gY4tn9OABui7por98yRlQUl7HYo63nPYPhCK3zMFcEOL8xjYot1cYYCGxE5yFxqkbX9fmbWEsRmx_BsgRPdraZ5DhvCES3BYstJAVctS-2LikGMK7veV7r6tEoKPvmKrkOKH90_-0GVvdG0GJn7Ccqz9OTWa1sE",
    "dq": "DYqOZnhR_1GZhNaMyVdAOcLt3Sw20TL90pEPSbYLGtcBLqZkyo9wNtMguYd_YFXHojF_iNwQW9IdYE7hVgA87tLEgM8S-1zQFVI2jGkBbqHisncQ4NdbEdIXxc3YHyCQmurPPW_EjKhyRKzHoalkJoUUSWF0S34MXoiFHIEae-s",
    "e": "AQAB",
    "key_size": 2048,
    "kty": "RSA",
    "n": "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11_ICDkGgS6W3ZWLts-hzwI3x65659kg4hVo9dbGoCJE3ZGF_eaetE30UhBUEgpGwrDrQiJ9zqprmcFfr3qvvkGjtth8Zgl1eM2bJcOwE7PCBHWTKWYs152R7g6Jg2OVph-a8rq-q79MhKG5QoW_mTz10QT_6H4c7PjWG1fjh8hpWNnbP_pv6d1zSwZfc5fl6yVRL0DV0V3lGHKe2Wqf_eNGjBrBLVklDTk8-stX_MWLcR-EGmXAOv0UBWitS_dXJKJu-vXJyw14nHSGuxTIK2hx1pttMft9CsvqimXKeDTU14qQL1eE7ihcw",
    "p": "0AZrdzBIpxDQggVh0x4GYBmNDuC8Ut_qOAKNLbpJLaWHFmeMjQRnXM8nxZfmhzAQ10XAS6n7TyFqK-PrhfmKWZ0g34UVfeXd4-D-gqegIDZ3TNwNCOBLOpwdDrHeB06ZdJ1o2OI1XLTO12PQN6PRUVKKF0dFdXV7NAM8YpJkxmE",
    "q": "zM_2m4uE2ldfNMOJmCMRm2S2NpiMOYi3Pp6Q6c4QtpF1up0Bak0Whox4F6VN6ydJjgolXFITufUU4XhT8p9WvDdCrY5u3NWbGMXMC426JPHXBKdHqQvAf3LFcbWNjrjowBktkPyDbB5sL3H8ey-q6tzGqLirZGZSKFiZ6J3OUFM",
    "qi": "O7leKcjIonKzTlI2EcShf4Vdlw-AvlQqAHmpGttHP0Vr--R4RteORtdXGUZC92GNaiHmkDLwak8ENfewKUP9xMyE_Psc5N090P_y9yKaIQnqN5QYe7quisqYtD64xP-568JaQCCqUtrVFT62jFhl0cVQ8Fy2oqdaKBufjLv-ssc",
}

SIMPLE_USER_CLAIMS = {
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US",
    },
    "birthdate": "1940-01-01",
}
SIMPLE_DISCLOSED_CLAIMS = {"given_name": None,
                           "family_name": None, "address": None}

STRUCTURED_USER_CLAIMS = SIMPLE_USER_CLAIMS
STRUCTURED_CLAIMS_STRUCTURE = {"address": {}}

STRUCTURED_DISCLOSED_CLAIMS = {
    "given_name": None,
    "family_name": None,
    "birthdate": None,
    "address": {"region": None, "country": None},
}

COMPLEX_USER_CLAIMS = {
    "verified_claims": {
        "verification": {
            "trust_framework": "de_aml",
            "time": "2012-04-23T18:25Z",
            "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
            "evidence": [
                {
                    "type": "document",
                    "method": "pipp",
                    "time": "2012-04-22T11:30Z",
                    "document": {
                        "type": "idcard",
                        "issuer": {"name": "Stadt Augsburg", "country": "DE"},
                        "number": "53554554",
                        "date_of_issuance": "2010-03-23",
                        "date_of_expiry": "2020-03-22",
                    },
                }
            ],
        },
        "claims": {
            "given_name": "Max",
            "family_name": "Meier",
            "birthdate": "1956-01-28",
            "place_of_birth": {"country": "DE", "locality": "Musterstadt"},
            "nationalities": ["DE"],
            "address": {
                "locality": "Maxstadt",
                "postal_code": "12344",
                "country": "DE",
                "street_address": "An der Weide 22",
            },
        },
    },
    "birth_middle_name": "Timotheus",
    "salutation": "Dr.",
    "msisdn": "49123456789",
}

COMPLEX_CLAIMS_STRUCTURE = {
    "verified_claims": {
        "verification": {
            "evidence": [
                {
                    "document": {
                        "issuer": {},
                    }
                }
            ]
        },
        "claims": {
            "place_of_birth": {},
        },
    }
}
COMPLEX_DISCLOSED_CLAIMS = {
    "verified_claims": {
        "verification": {
            "trust_framework": None,
            "time": None,
            "evidence": [{"type": None}],
        },
        "claims": {
            "given_name": None,
            "family_name": None,
            "birthdate": None,
            "place_of_birth": {"country": None},
        },
    },
}
