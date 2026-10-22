# 支払いつきのエージェントの呼び出し 3 回、予算 20,000、そして誰でも計算し直せる決済

[English](pilot51-settlement.md)

2026 年 10 月 22 日、00:00 から 03:00 UTC の間に、ある AI エージェントが別のエージェントを有料で 3 回呼び出しました。その記録は、弊社を信じなくても確かめられる形で決済されました。何が起きたか、弊社の外の人が何を確かめたか、そしてこれが何を示さないかを書きます。

## 起きたこと

買い手の予算は 20,000 JPY-testnet でした。呼び出しは 1 回 7,000 です。呼び出し A と B は支払われて実行され、合計は 14,000 になりました。呼び出し C も支払われて実行され、合計は 21,000 になりました。

各段は署名つきの記録(log)に入りました。予算、呼び出しごとの受け入れの基準、そして呼び出しごとの使用、支払い、応答した側の受領証です。合わせて 13 本です。log の checkpoint は OpenTimestamps で刻み、Bitcoin の block 972551 に錨を下ろしています。

決済は、この log を署名された予算と委任に照らして読みます。呼び出し C について、決済は次のように出します。

- 実行: `within_delegation`。応答した側は、許された事をした。
- 支払い: `budget_exceeded`。3 回目の支払いで、合計が予算を超えた。

呼び出し A と B には理由が付きません。記録の全部、束(bundle)、決済は [`pilot51/set2/`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2) に公開しており、この回の経緯は [Issue #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51) にあります。

同じ時間帯に、aeoess は同じ 3 回の呼び出しを自分たちの仕組み(Agent Passport System)で、予算 15,000 で回しました。そちらでは、呼び出し C は何も送る前に断られました([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6329364718))。1 つの状況に対する 2 つの作りです。片方は呼び出しの前に断り、もう片方は呼び出しの後に記録します。

## 弊社の外の人が確かめたこと

- **決済の計算し直し。** Poke-nushi が、公開したファイルから自分の機械で決済を計算し直し、出力の hash が一致しました。署名と OpenTimestamps の証明も確かめ、Bitcoin の header の view を Blockstream と mempool.space の header で block 972564 まで作り直しました。判定は変わらず、変わったのは錨の深さだけで、9 から 14 になりました([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6332669484))。
- **audit のバイト。** aeoess は、自分たちの側の呼び出し A と B の audit のファイルが、弊社のものとバイトまで同じだと報告しました([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6330218168))。
- **規則そのもの。** 決済の規則は仕様 [draft-oga-musubi-settlement](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/) として書いてあり、試験の見本(test vectors)が 128 件あります。ほかの作者が書いた 2 つの実装が、128 件すべてで弊社と一致しています。[aeoess/musubi-settle-core-check](https://github.com/aeoess/musubi-settle-core-check) と [kuangmi-bit/nenrin-independent-verifiers](https://github.com/kuangmi-bit/nenrin-independent-verifiers/tree/bbe455c/settle-core-v0) です。commit つきの一覧は [docs/INTEROP_TABLE.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/docs/INTEROP_TABLE.md) にあります。

## 自分で確かめる

    pipx run --spec 'nenrin-verify[ca2a]==0.7.0' musubi-verify --pilot51-set2
    pipx run --spec 'nenrin-verify[ca2a]==0.7.0' musubi-verify --settle-core

1 行目はこの回の決済を計算し直し、公開した hash(`18a19f8a...`)と比べます。2 行目は仕様の 128 件の見本を回します(30 秒ほど)。Python 3.11 以上が要ります。5 分の手引きは [QUICKSTART.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/QUICKSTART.md) にあります。

## これが示さないこと

- **本物のお金ではない。** 単位は JPY-testnet で、支払いの経路は署名つきの試験の送金です。お金は動いていません。
- **超過を防いではいない。** 決済は、後から記録しました。防ぐのは別の仕事で、同じ回の aeoess の行がそれをしました。
- **呼び出しの当事者は全部弊社。** 買い手、応答した側、log の運営者は、どれも弊社です。外の人は証人と読み手で、支払いの当事者ではありません。
- **外の計算し直しは弊社の道具を使った。** Poke-nushi が回したのは、弊社が公開した束に対する、弊社の companion の決済の道具です。独立した実行であって、companion の独立した実装ではありません。上の 2 つの独立した実装が当たっているのは settle core の規則で、companion ではありません。
- **外部監査はまだ。** 社内の敵対的な見直しで欠陥が見つかり、公開で一覧にして直しています。これは第三者の監査ではありません。
- **署名は誰が言ったかを示し、それが本当かは示さない。** 計算し直した決済が示すのは、公開したバイトが、公開した規則のもとで、公開した答えを出すことです。

## 壊してみてください

正しいと言われるより、間違っていると言われる方を望みます。[Issue #55](https://github.com/ogasurfproject-jpg/horizon-shield/issues/55) に「Break MUSUBI」の枠があります。署名された条件と食い違うのに権限の範囲内と決済される束、文に従う 2 つの読み手が同じバイトで食い違う例、覆われたバイトを変えても通る検査。バイトを持ってきてください。公開で回し直します。動いているサービスへの指摘は [SECURITY.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/SECURITY.md) からお願いします。
