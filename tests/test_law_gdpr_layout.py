"""
GDPR details the shared fetcher tests do not cover: the definitions of art. 4
(numbered points, no paragraphs), footnote references and the chapter
heading that follows art. 4 on the real page.
"""
from pathlib import Path

import pytest

from apkradar.law_fetcher import parse_articles

FIXTURE = Path(__file__).parent / "fixtures" / "gdpr_it_excerpt.html"
ARTICLES = ("4", "5", "6", "7", "9", "13", "28", "46")


@pytest.fixture(scope="module")
def texts():
    return parse_articles(FIXTURE.read_text(encoding="utf-8"), ARTICLES)


def test_extracts_articles_paragraphs_and_points(texts):
    for ref in (
        "4", "4(1)", "4(26)",
        "5", "5(1)", "5(1)(a)", "5(1)(f)", "5(2)",
        "6", "6(1)(a)", "6(1)(f)", "6(4)(e)",
        "7", "7(1)", "7(4)",
        "9", "9(1)", "9(2)(a)", "9(2)(j)",
        "13(1)(a)", "13(2)(f)",
        "28(3)(h)", "28(10)",
        "46", "46(2)(a)", "46(3)(b)",
    ):
        assert ref in texts, ref


def test_paragraph_text(texts):
    assert texts["7(1)"] == (
        "1. Qualora il trattamento sia basato sul consenso, il titolare del trattamento "
        "deve essere in grado di dimostrare che l'interessato ha prestato il proprio "
        "consenso al trattamento dei propri dati personali."
    )


def test_definitions_of_article_4_are_numbered_points(texts):
    assert texts["4(1)"].startswith(
        "1) «dato personale»: qualsiasi informazione riguardante una persona fisica"
    )
    assert texts["4"].startswith("Ai fini del presente regolamento s'intende per:")


def test_definition_sub_points_stay_in_the_definition(texts):
    assert " a) " in texts["4(16)"] and " b) " in texts["4(16)"]


def test_footnote_references_are_dropped(texts):
    assert texts["4(25)"].endswith("del Parlamento europeo e del Consiglio;")
    assert "(19)" not in texts["4"]


def test_following_chapter_heading_is_not_part_of_article_4(texts):
    assert "CAPO II" not in texts["4"]
    assert texts["4"].endswith("sulla base di un accordo tra due o più Stati.")
