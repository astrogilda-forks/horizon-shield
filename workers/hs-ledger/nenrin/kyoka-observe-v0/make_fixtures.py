# make_fixtures.py : writes the synthetic register pages in fixtures/, in the register's own shape (Shift_JIS, the
# table class re_disp, the seven columns as served on 2026-10-15). The businesses, people and addresses are invented;
# nothing here was copied from the register. Run: python3 -I make_fixtures.py
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
for name, html in pages.items():
    with open(os.path.join(HERE, "fixtures", name), "wb") as f:
        f.write(html.encode("cp932"))
print("wrote", len(pages), "fixtures")
