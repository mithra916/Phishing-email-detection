from unittest.mock import patch

from src.predict import predict_email


class FakeVectorizer:

    def transform(self, data):
        return data


class FakeModel:

    def predict_proba(self, data):
        return [[0.2, 0.8]]


def test_prediction_with_header_analysis():

    email = """\
From: Microsoft Support <support@example.com>
To: user@example.com
Reply-To: attacker@evil-example.com
Return-Path: attacker@evil-example.com
Subject: Urgent account verification
Authentication-Results: mx.example.com;
    spf=fail;
    dkim=pass;
    dmarc=fail
Received: from mail.example.com (192.168.1.10)

Please verify your account immediately.
"""

    with patch(
        "src.predict.get_emotion_score",
        return_value=0.5,
    ):

        result = predict_email(
            email,
            FakeModel(),
            FakeVectorizer(),
        )

    assert "header_analysis" in result

    assert (
        result["header_analysis"]["authentication"]["spf"]
        == "fail"
    )

    assert (
        result["header_analysis"]["authentication"]["dmarc"]
        == "fail"
    )

    assert (
        result["header_analysis"]["domains"]["reply_to_mismatch"]
        is True
    )

    assert len(result["reasons"]) > 0


def test_normal_email_header_analysis():

    email = """\
From: Alice <alice@example.com>
To: user@example.com
Reply-To: alice@example.com
Return-Path: alice@example.com
Subject: Meeting

Hello, see you tomorrow.
"""

    with patch(
        "src.predict.get_emotion_score",
        return_value=0.0,
    ):

        result = predict_email(
            email,
            FakeModel(),
            FakeVectorizer(),
        )

    assert "header_analysis" in result

    assert (
        result["header_analysis"]["domains"]["reply_to_mismatch"]
        is False
    )

    assert (
        result["header_analysis"]["domains"]["return_path_mismatch"]
        is False
    )