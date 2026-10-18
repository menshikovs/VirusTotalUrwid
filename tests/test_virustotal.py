from virustotal import extract_stats


def test_extract_stats():
    report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 3,
                }
            }
        }
    }

    expected = {
        "malicious": 5,
        "suspicious": 2,
        "harmless": 60,
        "undetected": 3,
    }

    result = extract_stats(report)

    assert result == expected
