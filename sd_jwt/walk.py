import json
import logging
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("sd_jwt")


def simple_find_by_key(_: Dict, key: str):
    """
    This function defines the default behavior for find_fn (see below), which is
    finding elements in the dictionary `structure` simply by looking up the key
    `key`.
    """
    return key


def by_structure(
    structure: Dict,
    obj: Dict,
    fn: Callable[[str, str, Optional[Any]], Tuple[str, Any]],
    find_fn=simple_find_by_key,
):
    """
    This helper function allows traversing a nested dictionary using a given
    structure as the guide. A function that is passed as an argument is called
    for every leaf node in obj that is not contained in the structure object.

    The function fn has the following signature: fn(key: str, value: str,
    value_in_structure: Optional[Any]) -> Tuple[str, Any]

    value_in_structure is only passed if the structure already contains a value
    at this point in the structure.

    The function must return a tuple consisting of a new key and a new value for
    the output structure.

    The argument find_fn allows for a translation between keys in structure and
    obj. It is called with structure and the key as found in obj as arguments
    and is expected to return the key that is to be used to access the element
    in structure.

    See examples below!
    """
    logger.debug(f"Walking in: {structure} using {obj} on {fn}")
    out = {}
    for key_in_obj, value_in_obj in obj.items():
        logger.debug(f"{key_in_obj}: {value_in_obj}")
        try:
            key_in_structure = find_fn(structure, key_in_obj)
            value_in_structure = structure[key_in_structure]

            if isinstance(value_in_structure, dict):
                out[key_in_structure] = by_structure(
                    value_in_structure, value_in_obj, fn, find_fn
                )
            elif isinstance(value_in_structure, list):
                out[key_in_structure] = list(
                    by_structure(value_in_structure[0], item, fn, find_fn)
                    for item in value_in_obj
                )
            else:
                new_key, new_value = fn(
                    key_in_structure, value_in_obj, value_in_structure
                )
                out[new_key] = new_value
        except KeyError:
            new_key, new_value = fn(key_in_obj, value_in_obj)
            out[new_key] = new_value
    return out


if __name__ == "__main__":
    # Example 1

    def test_fn(key, value, value_in_structure=None):
        return (key, f"called fn({key}, {value}, {value_in_structure})")

    structure0 = {}

    raw0 = {
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

    expected0 = {
        "sub": "called fn(sub, 6c5c0a49-b589-431d-bae7-219122a9ec2c, None)",
        "given_name": "called fn(given_name, John, None)",
        "family_name": "called fn(family_name, Doe, None)",
        "email": "called fn(email, johndoe@example.com, None)",
        "phone_number": "called fn(phone_number, +1-202-555-0101, None)",
        "address": "called fn(address, {'street_address': '123 Main St', 'locality': 'Anytown', 'region': 'Anystate', 'country': 'US'}, None)",
        "birthdate": "called fn(birthdate, 1940-01-01, None)",
    }

    output0 = by_structure(structure0, raw0, test_fn)
    print(json.dumps(output0, indent=4))
    assert output0 == expected0

    structure1 = {
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

    raw1 = {
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
        "unverified_family_name": "Meier",
        "unverified_birthdate": "1956-01-28",
    }

    expected1 = {
        "verified_claims": {
            "verification": {
                "trust_framework": "called fn(trust_framework, de_aml, None)",
                "time": "called fn(time, 2012-04-23T18:25Z, None)",
                "verification_process": "called fn(verification_process, f24c6f-6d3f-4ec5-973e-b0d8506f3bc7, None)",
                "evidence": [
                    {
                        "type": "called fn(type, document, None)",
                        "method": "called fn(method, pipp, None)",
                        "time": "called fn(time, 2012-04-22T11:30Z, None)",
                        "document": {
                            "type": "called fn(type, idcard, None)",
                            "issuer": {
                                "name": "called fn(name, Stadt Augsburg, None)",
                                "country": "called fn(country, DE, None)",
                            },
                            "number": "called fn(number, 53554554, None)",
                            "date_of_issuance": "called fn(date_of_issuance, 2010-03-23, None)",
                            "date_of_expiry": "called fn(date_of_expiry, 2020-03-22, None)",
                        },
                    }
                ],
            },
            "claims": {
                "given_name": "called fn(given_name, Max, None)",
                "family_name": "called fn(family_name, Meier, None)",
                "birthdate": "called fn(birthdate, 1956-01-28, None)",
                "place_of_birth": {
                    "country": "called fn(country, DE, None)",
                    "locality": "called fn(locality, Musterstadt, None)",
                },
                "nationalities": "called fn(nationalities, ['DE'], None)",
                "address": "called fn(address, {'locality': 'Maxstadt', 'postal_code': '12344', 'country': 'DE', 'street_address': 'An der Weide 22'}, None)",
            },
        },
        "unverified_family_name": "called fn(unverified_family_name, Meier, None)",
        "unverified_birthdate": "called fn(unverified_birthdate, 1956-01-28, None)",
    }

    output1 = by_structure(structure1, raw1, test_fn)
    print(json.dumps(output1, indent=2))
    assert output1 == expected1

    # Example 2

    expected2 = {
        "verified_claims": {
            "verification": {
                "trust_framework": "called fn(trust_framework, de_aml, called fn(trust_framework, de_aml, None))",
                "time": "called fn(time, 2012-04-23T18:25Z, called fn(time, 2012-04-23T18:25Z, None))",
                "verification_process": "called fn(verification_process, f24c6f-6d3f-4ec5-973e-b0d8506f3bc7, called fn(verification_process, f24c6f-6d3f-4ec5-973e-b0d8506f3bc7, None))",
                "evidence": [
                    {
                        "type": "called fn(type, document, called fn(type, document, None))",
                        "method": "called fn(method, pipp, called fn(method, pipp, None))",
                        "time": "called fn(time, 2012-04-22T11:30Z, called fn(time, 2012-04-22T11:30Z, None))",
                        "document": {
                            "type": "called fn(type, idcard, called fn(type, idcard, None))",
                            "issuer": {
                                "name": "called fn(name, Stadt Augsburg, called fn(name, Stadt Augsburg, None))",
                                "country": "called fn(country, DE, called fn(country, DE, None))",
                            },
                            "number": "called fn(number, 53554554, called fn(number, 53554554, None))",
                            "date_of_issuance": "called fn(date_of_issuance, 2010-03-23, called fn(date_of_issuance, 2010-03-23, None))",
                            "date_of_expiry": "called fn(date_of_expiry, 2020-03-22, called fn(date_of_expiry, 2020-03-22, None))",
                        },
                    }
                ],
            },
            "claims": {
                "given_name": "called fn(given_name, Max, called fn(given_name, Max, None))",
                "family_name": "called fn(family_name, Meier, called fn(family_name, Meier, None))",
                "birthdate": "called fn(birthdate, 1956-01-28, called fn(birthdate, 1956-01-28, None))",
                "place_of_birth": {
                    "country": "called fn(country, DE, called fn(country, DE, None))",
                    "locality": "called fn(locality, Musterstadt, called fn(locality, Musterstadt, None))",
                },
                "nationalities": "called fn(nationalities, ['DE'], called fn(nationalities, ['DE'], None))",
                "address": "called fn(address, {'locality': 'Maxstadt', 'postal_code': '12344', 'country': 'DE', 'street_address': 'An der Weide 22'}, called fn(address, {'locality': 'Maxstadt', 'postal_code': '12344', 'country': 'DE', 'street_address': 'An der Weide 22'}, None))",
            },
        },
        "unverified_family_name": "called fn(unverified_family_name, Meier, called fn(unverified_family_name, Meier, None))",
        "unverified_birthdate": "called fn(unverified_birthdate, 1956-01-28, called fn(unverified_birthdate, 1956-01-28, None))",
    }

    # Take the output of example 1 as the structure this time.
    output2 = by_structure(output1, raw1, test_fn)
    print(json.dumps(output2, indent=2))

    assert output2 == expected2

    def test_fn_with_renaming(key, value, value_in_structure=None):
        return (key + "X", f"called fn({key}, {value}, {value_in_structure})")

    structure3 = {}

    raw3 = {
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

    expected3 = {
        "subX": "called fn(sub, 6c5c0a49-b589-431d-bae7-219122a9ec2c, None)",
        "given_nameX": "called fn(given_name, John, None)",
        "family_nameX": "called fn(family_name, Doe, None)",
        "emailX": "called fn(email, johndoe@example.com, None)",
        "phone_numberX": "called fn(phone_number, +1-202-555-0101, None)",
        "addressX": "called fn(address, {'street_address': '123 Main St', 'locality': 'Anytown', 'region': 'Anystate', 'country': 'US'}, None)",
        "birthdateX": "called fn(birthdate, 1940-01-01, None)",
    }

    output3 = by_structure(structure3, raw3, test_fn_with_renaming)
    print(json.dumps(output3, indent=4))
    assert output3 == expected3
