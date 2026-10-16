# make_fixtures.py : writes the synthetic register pages in fixtures/, in the register's own shape (Shift_JIS, the
# table class re_disp, the seven columns as served on 2026-10-15; and, since 0.2.0, the detail page ksGaiyo.do with
# the tables re_summ, re_summ_3, re_summ_4 and re_summ_5 as served on 2026-10-16). The businesses, people, telephone
# numbers and addresses are invented; nothing here was copied from the register. Run: python3 -I make_fixtures.py
import os
HERE = os.path.dirname(os.path.abspath(__file__))
HEAD = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"><title>国土交通省 | 建設業者 検索</title></head><body>\n<div>データ閲覧 ＞ 建設業者</div>\n'
FOOT = '<div>（補足説明）「保険加入状況」は大臣許可業者を先行して掲載いたします。</div>\n<div>Copyright&copy; 2008-2019 MLIT Japan. All Rights Reserved.</div></body></html>\n'
TH = '<tr>\n <th>No.</th>\n <th>許可行政庁</th>\n <th>許可番号</th>\n <th>商号又は名称</th>\n <th>代表者名</th>\n <th>営業所名</th>\n <th>所在地</th>\n</tr>\n'
def row(i, auth, no, name, rep, office, addr):
    s = 'style="text-align:left; white-space : nowrap;"'
    return ('<tr>\n <td style="text-align:right;">%d</td>\n <td %s>%s</td>\n <td %s title="licenseNo">第%s号</td>\n'
            ' <td style="text-align:left;"><a href="javascript:void(0);" onclick="js_ShowDetail(\'01%s\')">%s</a></td>\n'
            ' <td %s>%s</td>\n <td style="text-align:left;">%s</td>\n <td style="text-align:left;">%s</td>\n</tr>\n') % (i, s, auth, s, no, no, name, s, rep, office, addr)
def page(rows, total=None):
    n = len(rows) if total is None else total
    form = '<form name="ksModel"><input type="hidden" name="resultCount" value="%d"><input type="hidden" name="pageCount" value="%d"></form>\n' % (n, (n + 49) // 50)
    return HEAD + form + '<table class="re_disp">\n' + TH + ''.join(rows) + '</table>\n' + FOOT
pages = {
  "minister_listed.bin": page([
    row(1, "関東地方整備局", "004321", "（株）見本建設", "見本　一郎", "本店", "東京都千代田区見本町１－２－３"),
    row(2, "関東地方整備局", "004321", "（株）見本建設", "見本　一郎", "横浜支店", "神奈川県横浜市中区見本通４－５"),
  ]),
  "governor_shared_number.bin": page([
    row(1, "宮城県", "012345", "（有）例示内装", "例示　花子", "主たる営業所", "宮城県仙台市青葉区例示１－１"),
    row(2, "神奈川県", "012345", "例示工務店", "例示　太郎", "主たる営業所", "神奈川県平塚市例示町２－２"),
    row(3, "大阪府", "012345", "（株）例示設備", "例示　次郎", "主たる営業所", "大阪府大阪市北区例示３－３"),
  ]),
  "minister_truncated.bin": page([
    row(1, "関東地方整備局", "004321", "（株）見本建設", "見本　一郎", "札幌支店", "北海道札幌市中央区見本１－１"),
    row(2, "関東地方整備局", "004321", "（株）見本建設", "見本　一郎", "仙台支店", "宮城県仙台市青葉区見本２－２"),
  ], total=73),
  "governor_page_full.bin": page([
    row(1, "宮城県", "012345", "（有）例示内装", "例示　花子", "主たる営業所", "宮城県仙台市青葉区例示１－１"),
    row(2, "大阪府", "012345", "（株）例示設備", "例示　次郎", "主たる営業所", "大阪府大阪市北区例示３－３"),
  ], total=60),
  "entities.bin": page([
    row(1, "関東地方整備局", "004321", "見本&amp;lt;建設&#12354;", "見本　一郎", "本店", "東京都千代田区見本町１"),
  ]),
  "bad_entity.bin": page([
    row(1, "関東地方整備局", "004321", "見本&#9999999;", "見本　一郎", "本店", "東京都千代田区見本町１"),
  ]),
  "not_listed.bin": HEAD + '<div>「該当するデータが存在しません。」</div>\n' + FOOT,
  "changed_columns.bin": page([]).replace("<th>代表者名</th>", "<th>代表者</th>"),
}
# ---- the detail page (ksGaiyo.do) ----
LETTERS = ["土", "建", "大", "左", "と", "石", "屋", "電", "管", "\u5915", "鋼", "筋", "舗", "し<br>ゅ", "板", "ガ", "塗", "防", "内",
           "機", "絶", "通", "園", "井", "具", "水", "消", "清", "解"]
def trade_table(vals):
    head = '<tr class="re_summ_ev">\n <th rowspan="2">許可を受けた<br>建設業の種類</th>\n' + ''.join(' <td>%s</td>\n' % l for l in LETTERS) + '</tr>\n'
    row = '<tr class="re_summ_odd">\n' + ''.join(' <td>%s</td>\n' % v for v in vals) + '</tr>\n'
    return '<table class="re_summ_3">\n' + head + row + '</table>\n'
def detail(lic, kana, name, rep, addr, tel, vals, grants, validity, letters=None):
    summ = ('<table class="re_summ">\n <tr>\n <th>許可番号</th>\n <td>%s</td>\n </tr>\n'
            ' <tr>\n <th>商号又は名称</th>\n <td><p class="phonetic">%s</p>%s</td>\n </tr>\n'
            ' <tr>\n <th>代表者の氏名</th>\n <td><p class="phonetic">ミホン　タロウ</p>%s</td>\n </tr>\n'
            ' <tr>\n <th>主たる営業所の所在地</th>\n <td>〒000-0000<br>%s</td>\n </tr>\n'
            ' <tr>\n <th>電話番号</th>\n <td>%s</td>\n </tr>\n</table>\n') % (lic, kana, name, rep, addr, tel)
    s2 = '<table class="re_summ_2">\n <tr>\n <th>法人・個人区分</th>\n <td>法人</td>\n </tr>\n</table>\n'
    t4t = '<table class="re_summ_4tit">\n <tr>\n <th>No.</th>\n <td>許可年月</td>\n </tr>\n</table>\n'
    t4 = '<table class="re_summ_4">\n' + ''.join(' <tr bgcolor="#f3f3f3">\n <th>%d</th>\n <td><a href="javascript:void(0);">%s</a></td>\n </tr>\n' % (i + 1, g) for i, g in enumerate(grants)) \
         + ' <tr>\n <th></th>\n <td></td>\n </tr>\n</table>\n'
    t5 = '<table class="re_summ_5">\n <tr>\n <th>許可の有効期間</th>\n <td>%s</td>\n </tr>\n <tr>\n <th>許可条件</th>\n <td>&nbsp;</td>\n </tr>\n</table>\n' % validity
    t3 = trade_table(vals)
    if letters: t3 = t3.replace('<td>%s</td>' % letters[0], '<td>%s</td>' % letters[1], 1)
    return HEAD + summ + s2 + t3 + t4t + t4 + t5 + trade_table([v or "&nbsp;" for v in vals]) + FOOT
V = [""] * 29
def vals(**k):
    v = list(V)
    for i, c in k.items(): v[int(i[1:])] = c
    return v
pages.update({
  # 神奈川県知事許可 第012345号: 建築一式 特定, 内装仕上 一般, granted 令和5年, within its period on 2026-10-15
  "detail_governor.bin": detail("神奈川県知事許可　第012345号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2", i18="1"), ["R05/04/01"], "R05年04月01日からR10年03月31日まで"),
  # 国土交通大臣許可 第004321号: renewed, the period shown starts after the day observed, two grant dates
  "detail_minister_renewed.bin": detail("国土交通大臣許可　第004321号", "ミホンケンセツ", "（株）見本建設", "見本　一郎", "東京都千代田区見本町１－２－３", "00-0000-0000",
      vals(i0="2", i1="2", i7="1", i28="1"), ["R08/12/01", "R06/05/10"], "R08年12月01日からR13年11月30日まで"),
  "detail_other_licence.bin": detail("神奈川県知事許可　第054321号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2"), ["R05/04/01"], "R05年04月01日からR10年03月31日まで"),
  "detail_changed_columns.bin": detail("神奈川県知事許可　第012345号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2"), ["R05/04/01"], "R05年04月01日からR10年03月31日まで", letters=("\u5915", "タ")),
  "detail_bad_value.bin": detail("神奈川県知事許可　第012345号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="3"), ["R05/04/01"], "R05年04月01日からR10年03月31日まで"),
  "detail_bad_date.bin": detail("神奈川県知事許可　第012345号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2"), ["R05/02/30"], "R05年02月30日からR10年03月31日まで"),
  "detail_period_mismatch.bin": detail("神奈川県知事許可　第012345号", "レイジコウムテン", "例示工務店", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2"), ["R05/04/01"], "R04年04月01日からR09年03月31日まで"),
  "detail_other_name.bin": detail("神奈川県知事許可　第012345号", "ベツメイ", "（株）別名", "例示　太郎", "神奈川県平塚市例示町２－２", "0000-00-0000",
      vals(i1="2"), ["R05/04/01"], "R05年04月01日からR10年03月31日まで"),
})
for name, html in pages.items():
    with open(os.path.join(HERE, "fixtures", name), "wb") as f:
        f.write(html.encode("cp932"))
print("wrote", len(pages), "fixtures")
