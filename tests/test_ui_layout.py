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
    assert text.count('href="https://github.com/kadidalax/vkomari"') == 2
    assert "github.com/kadidalax/vkomari-cf" not in text
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
    assert 'TICK_SECONDS = 1' in scheduler


def test_load_presets_have_stable_seeded_spread():
    text = html()
    with open(os.path.join(ROOT, "static", "js", "data.js"), encoding="utf-8") as f:
        data = f.read()
    assert "profileSeed(key)" in text
    assert "client_uuid:crypto.randomUUID()" in text
    presets = data[data.index("loadPresets: {"):data.index("// 3.", data.index("loadPresets: {"))]
    assert "cpu_min" not in presets
    assert "cpu_max" not in presets
    assert "CPU最低" not in text
    assert "CPU最高" not in text
    assert "x-model=\"form.cpu_min\"" not in text
    assert "x-model=\"form.cpu_max\"" not in text
    assert "this.form.cpu_min" not in text
    assert "this.form.cpu_max" not in text
    assert 'src="js/data.js?v=' in text
    assert 'src="js/api.js?v=' in text


def test_refresh_load_changes_seed_and_templates_keep_ranges():
    text = html()
    assert "loadSeed:''" in text
    assert "if(showToast)this.loadSeed=crypto.randomUUID()" in text
    assert "+this.loadSeed" in text
    assert "band=(a,b,k,minWidth=0,round=r1)" in text
    assert "['mem_min','mem_max','mem',8]" in text
    assert "['disk_min','disk_max','disk',8]" in text
    assert "band(a,b,k,0,Math.round)" in text
    apply_template = text[text.index("applyTemplate(t){"):text.index("async deleteTemplate", text.index("applyTemplate(t){"))]
    assert "refreshLoad" not in apply_template


def test_spa_entry_disables_stale_html_cache():
    with open(os.path.join(ROOT, "main.py"), encoding="utf-8") as f:
        main = f.read()
    assert '"Cache-Control": "no-store"' in main


if __name__ == "__main__":
    test_toolbar_filter_and_footer_layout_markers()
    test_cards_use_saved_order_and_group_name_sort_buttons()
    test_default_intervals_are_komari_one_cfmonitor_three()
    test_load_presets_have_stable_seeded_spread()
    test_refresh_load_changes_seed_and_templates_keep_ranges()
    test_spa_entry_disables_stale_html_cache()
