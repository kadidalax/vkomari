import os


ROOT = os.path.dirname(os.path.dirname(__file__))


def html():
    with open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8") as f:
        return f.read()


def test_toolbar_filter_and_footer_layout_markers():
    text = html()
    assert 'data-ui="top-actions"' in text
    assert 'data-ui="filter-row"' in text
    assert 'data-ui="footer-line"' in text
    assert text.index('title="GitHub"') < text.index('@click="exportNodes"')
    assert text.index('x-model="activeGroup"') < text.index("@click=\"batchAction('start')\"") < text.index('@click="openModal()"')


def test_cards_use_saved_order_and_group_name_sort_buttons():
    text = html()
    assert "@click.stop=\"sortGroupByName(group,'asc')\"" in text
    assert "@click.stop=\"sortGroupByName(group,'desc')\"" in text
    assert "sortGroupByName(group,dir)" in text
    assert "nodesInGroup(g){return this.filteredNodes.filter(n=>(n.group_name||'')===g)}" in text
    assert "sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 2xl:grid-cols-6" in text


def test_default_intervals_are_komari_one_cfmonitor_three():
    text = html()
    assert "report_interval:1" in text
    assert "this.form.report_interval=1" in text
    assert "this.form.report_interval=3" in text
    with open(os.path.join(ROOT, "scheduler.py"), encoding="utf-8") as f:
        scheduler = f.read()
    assert 'seconds=1' in scheduler


if __name__ == "__main__":
    test_toolbar_filter_and_footer_layout_markers()
    test_cards_use_saved_order_and_group_name_sort_buttons()
    test_default_intervals_are_komari_one_cfmonitor_three()
