## DirLocker(Directory Locker)
指定したディレクトリ配下のファイルを暗号化し安全に管理する為のプログラム\
・ファイル転送時の暗号化\
・保存用ディスクの暗号化 etc...


---------
## 暗号化ホスト
フォルダのロック ： `./user lock`\
フォルダのアンロック : `./user unlock "復号コード"`



## 復号ホスト
暗号ホストのセットアップ(公開鍵の新規作成) : `./host setup "PEMファイルパスワード"`\
復号キーのデコード&デクリプト : `./host retrieve "PEMファイルのパスワード" "復号キー"`

---------


※悪用厳禁\
※本プログラムには一部ファイルの暗号化・削除を伴うコードが含まれます. 本プログラムによって不法行為,直接損害,間接損害,付随損害等は発生の経緯を問わずいかなる責任も負いません.
