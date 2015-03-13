# Reverse-engineering-library

①serach_all_address(exe_path,assmble)：第一引数がファイルのパス、第二引数は、文字列で"pushf "このように宣言してあげると、逆アセンブルしたときに、指定したアセンブリ宣言を探し出して、リストでアドレスを返します。

②api_address(exe_path):第一引数にファイルパスを指定してあげる。内部と外部のAPIを表示してくれる。

③find_bad_address(api):第一引数には、API名を文字列として指定してあげると、そのAPIのアドレスを返します。

④serach_address(exe_path,assmble,address,step):第一引数は、exe_path、第二引数は、アセンブリ宣言を文字列で指定する、第三引数は、serach_all_addressなどで得られたアドレス。第四引数は、何バイトのステップまで読み込むか指定できる。返却値は、見つけた場合リストでアドレスを返す。

⑤disasmble(buffer_t):第一引数は、バイナリデータを挿入します。挿入したバイナリデータをアセンブリに直します。
