# Operator log extracts cited in the manuscript (marked with a dagger)

Verbatim lines from the operator's private Japanese work log (hs-core-private/handoff/PROGRESS_runbook_20260926.md), released only where the manuscript relies on them. Line numbers are the log's own. Nothing else from the log is public. No secret values appear in these lines.

## Log line 785

- 2026-10-04 10:5x メール: kuangmi-bit が A2A Discussion #1631(discussioncomment-18738206)で interop-v0 を仕様だけから独立実装(Python、did:key を手書き解決、cryptography、a2a-python の RFC 8785 正規化、こちらのソースは不読)= 5/5 の verdict signature、21 digest 全一致、署名 edge 10/10・caller 5/5・provider 6/6・witness 9/10(10 本目は forged の改ざん分)、変異 3 種で拒否 = 初の独立実装。仕様の穴 5 点を報告、番人が全部こちらの文面で確認して直した(未 push): (1) 署名入力 = 生 64 バイト Ed25519、標準 base64、canonical(preimage) の UTF-8、JWS 封筒なし(両 SPEC、delegation SPEC の古い「No DID/JWS」行も削除、sign.mjs と sign_exec.mjs と VATE_MAPPING の注記も。npm 版 nenrin_verify.mjs の注記は配布物と byte 固定なので次の版で) (2) R4 の fail-closed は hop の集計に限る、disagreement は所見で task の拒否ではない (3) invalid_timestamp は理由で code ではない(execution_invalid の reason) (4) 所見 9 つを全部定義、一覧から漏れていた declared_executed_divergence を追加 (5) linkage は 1 つだけ reconcile した時だけ評価、提示されただけの非 reconcile 受領証を指すと linkage_receipt_mismatch。新しい interop-v0.1(13 本、interop-v0 は不変、2 つで 14 の refusal code を全部): linkage_unpresented / linkage_unreconciled / self_authorized / witness_is_party / task_id_mismatch / task_id_missing / incomplete_pair / provider_sig_invalid / non_utc_timestamp / evidence_malformed / preflight_without_grant / preflight_invalid / preflight_signature_invalid。JS 13/13、Python 版 13/13(同作者なので独立ではない)、interop-v0 5/5、provenance と execution の敵試験 ALL PASS。返信案 ops-private/interop_20261004/reply_1631_kuangmi.md(81d79030、560 語、self_authorized と R1 の区別の訂正、検証器は本人の repo で公開を依頼、README に名前を載せてよいか尋ねる)

## Log line 787

- 2026-10-04 11:2x TOshi「なんの穴だ、何回も確認させたよな」→ 番人の答え: 穴は検証器の誤りではなく仕様書の文章と実装のずれ。これまでの確認は全部コード対コード(JS と Python 移植、変異試験、自分の検証器が作った expected)で、「文章だけで別人が実装できるか」を一度も試していなかった = 番人の落ち度。白紙からの試験(clean-room)を実施: エージェントに仕様 3 本と束だけ(ソース・expected・ネットなし)。1 回目(9d397f6d の文章)13/18、推測 11 箇所以上(束の形式、did:key、拒否時の所見、連鎖、schema の誤記ほか)。→ provenance-v0/VERIFIER.md(規範の手順書、束・基本関数・preimage 表・手順 0〜6・連鎖・集合としての verdict signature・外の端の規則と既知の弱点 = 日付の解釈が 2026-02-30 や 24 時を通す)を作成、delegation SPEC の schema の誤記と evidence_id の定義を修正、PROVENANCE の所見定義を VERIFIER と一致。2 回目(新しいエージェント)18/18、束に効く推測 0、canonical の見本 9/9。記録 ops-private/interop_20261004/cleanroom/(round1/round2 の verify と GAPS)。未 push: VERIFIER.md 2e244a4c、PROVENANCE.md e482f450、delegation SPEC 636323f7。kuangmi への追記の返信案 reply_1631_kuangmi_followup.md。次の版の npm/PyPI で日付の厳格化

## Log line 797

- 2026-10-04 13:43 kuangmi-bit が #1631 に 2 本目の独立実装を報告: VERIFIER.md(65ae7d0f)の文章だけから 18/18(先週の旧仕様からの実装は 8/18)、5 節が彼のコードの穴 2 つ(末尾改行、prev の absent と null)を捕まえた、残る割れ 4 点、interop-v0.2/edge の PR を申し出。番人: 2 点(理由と拒否コードの区別、action_binding の理由の順)を VERIFIER.md に反映(111c45a6、未 commit)、返信下書き ops-private/interop_20261004/reply_1631_kuangmi_second.md(fe40d793、PR 受諾、要素の型と非 object のキーは PR で規則として決める、名前の掲載の許可を再度尋ねる)。うちの JS と Python は末尾改行と全角数字を拒否することを確認済み

## Log line 1018

- 2026-10-08 23:3x TSUNAGI v1 と nenrin-verify 0.4.9 を用意(番人、未 push)。置き場 ops-private/tsunagi_v1_20261008/(tsunagi_v1.patch 5d619275、台本 toshi_tsunagi_v1.sh 784a042e、#29 への返信 reply_29_tsunagi_v1.md、参加募集の issue 文 issue_join_tsunagi.md)。中身: (1) 審判つきの升 batch_referee = 盤が fixtures を一括で渡し、返った verdict signature を expected.json と盤自身が照合(符号は集合、VERIFIER.md 4 節)。外部コードを走らせる前に corpus を読み込み、盤の道具・corpus・生成器を snapshot、走行後に変わっていたら戻して不合格。参照 JS・Go・PyPI 版(新行 hs-nenrin-pypi)は審判つき、kuangmi-bit は本人の runner の行を残し、verify() を呼ぶだけの adapter で審判つきの行を併設。(2) 毎晩の新しい束: conformance-v0 の攻撃係が新しい鍵で 40 束を署名し、一括で読める全実装に同じ束を渡して食い違いを列挙(凍った答えなし)。(3) history.json(連続合格回数・commit の移動)、badges/<id>.json(shields.io)、--local ID=PATH、PR の行をその場で走らせる tsunagi-preview.yml(読み取り専用 token)。(4) PyPI 0.4.9 = nenrin-tsunagi(run/score/row/batch-in/list、3 corpus を同梱、盤と同じ審判)、検証器は不変。parity CI の paths に interop を追加。番人の手元で盤 20/20、審判つき 12、外部 10。独立の検証役のレビュー(差分の非 object で盤が落ちる、出力サイズ無制限、走行中の改変、両方欠落を一致扱い、表の | など)を全部直した。初夜の発見: 新しい束 40 のうち 2 束(grant.action と executed_action が両方 null / 両方 0)で kuangmi-bit の v0・v02_edge が accepted、参照 3 実装は refused execution_invalid。VERIFIER.md 5 節「missing, null, false, 0 or "" なら E1 は action_diverged」= kuangmi-bit 側の読み違いの公算。push と盤の本番確認の後に番人が #29 に報告と issue を出す。

## Log line 1205

- 2026-10-13 09:1x 番人: #13 の型を deploy 中の全 worker で監査(Explore エージェント、37 worker、16 か所)。最重要 2 つを直した: 扉の登録簿 = 読み込み失敗で {} を書き戻し、誰でも叩ける POST /watch で他の行を全部消して ok:true(番人が旧コードで再現: 3 行が 1 行に)、hs-hearing の fetchPublished = 公開名簿の取得失敗で「加盟店 0 件」(8/20 の直しが効いていなかった)。patch gate_hearing_read_failure.patch(f477ff8b…、試験 扉 10・hearing 5、旧コードで落ちる、扉 run_all 35/35、hearing 20 本)。前の ledger の patch と合わせて 1 回で push・配る台本 toshi_fix_1013.sh(偽 git・偽 gh で 1〜3 段を通し試験)。単独の toshi_ledger_cite_verify.sh は .SUPERSEDED に改名(使わない)。残り(未着手): 扉 readHistory と is_verified/lookup_server の「absent」、hearing の resources/read、hs-webmcp・hs-us-report・hs-gyosha-check・hs-kira-line・hs-kira-group。別件の不具合: hs-kira-line handleGyoshaCheck が /check の返す {result} でなく risk_level/summary を読み、いつも「調査中」と返す。

## Log line 1233

- 2026-10-13 20:4x fix7 完了(TOshi): PUSHED c2bb3e02、扉 deploy_gate.sh gate_commit c2bb3e026540・card 0.4.20 公式 SDK verify・/health sweep single-flight-20261013(SWEEP_LEASE_DO と migration v1 適用)、hs-us-report 7be3416f・hs-kira-line 11d55a1d・ai-council 29018d6e、hs-hearing は Actions(2.3.2-rmw)。prod_fix_check 20 行中 19 OK、ledger/head だけ curl 20 秒切れ。番人が Chrome で実測: /ledger/head は HTTP 200・n=95・鎖は無傷、ただし 20.5 秒(entry を 1 件ずつ順に KV から読む歩き方、前からある遅さ)。fix8(fix8_1013.mbox d0235859…、toshi_fix8_1013.sh ff53ec64…): 鎖の entry を 24 件ずつ並べて先読み、歩き方・hash・出力は不変、/health chain_read prefetch-parallel-20261013、prod_fix_check は 60 秒待ち + 1 行。試験 旧 3/7 落ち → 新 7/7、既存 15 + GCP 緑、ci_mirror 緑、am 同 tree、偽 HOME 1〜2 段 OK。TOshi の実行待ち。

## Log line 1234

- 2026-10-13 20:5x fix8 完了(TOshi): PUSHED 2bfb472d、gitleaks・public-boundary 緑、hs-ledger deploy(Version afd29084、binding 5 本確認)。/health chain_read prefetch-parallel-20261013、/ledger/head 20.5 秒 → 1.49 秒(n=95、head 1fda4f12…、鎖無傷)。prod_fix_check 21/21 一致。これで 2026-10-13 の一連(fix3〜fix8: 読み込み失敗の型、同時更新 HIGH 4 + MEDIUM 13、検証材料、見張り)は全部本番。npm nenrin-verify 0.5.1 / PyPI 0.5.3 は出し直し不要(sdk・sdk-python は今日一行も変わっていない。台帳の hash・entry 形式・番号はバイト不変。変わったのはサーバー側と検証材料)。出し直すのは adequacy-v0 の提案 9 件を正式な見本集に採るときか、検証器の規則を変えるとき。

