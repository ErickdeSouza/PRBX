# APK Inspector

Ferramentas em Rust para inventariar APKs e preparar a árvore de arquivos isolada do runtime em desenvolvimento. O inspetor não executa nem altera o APK; o preparador ainda não executa código Android.

## Uso

```powershell
cargo run --release -- "C:\caminho\para\app.apk"
```

Para incluir componentes, permissões, métodos nativos declarados e imports/exports ELF:

```powershell
cargo run --release -- "C:\caminho\para\app.apk" --symbols
```

Testes:

```powershell
cargo test
```

## Preparar um APK para o runtime

O primeiro comando do runtime valida o manifesto e prepara as bibliotecas `arm64-v8a`, mantendo os arquivos do app numa pasta por pacote. Por padrão, usa o diretório de dados do usuário; `--data-dir` permite escolher outro local:

```powershell
cargo run --release --bin prbx-runtime -- prepare "C:\caminho\para\app.apk"
cargo run --release --bin prbx-runtime -- prepare "C:\caminho\para\app.apk" --data-dir "C:\dados\prbx\apps"
```

Em Linux, um teste com diretório explícito fica assim:

```sh
cargo run --release --bin prbx-runtime -- prepare "$HOME/Downloads/app.apk" --data-dir "$HOME/.local/share/prbx/apps"
```

Para `com.roblox.client`, o preparador cria `install/apk/base.apk`, `install/native/arm64-v8a/`, `install/assets/` e diretórios separados para `data/`, `data_de/`, `cache/`, `files/` e `storage/Delta/`. Os assets são extraídos preservando sua estrutura de subpastas, com limites de 256 MiB por arquivo, 2 GiB no total e 100.000 arquivos; caminhos absolutos, travessia de diretório e nomes incompatíveis com Windows são rejeitados. Atualizações são montadas em staging e substituem a instalação anterior somente depois da extração completa; dados, cache e armazenamento do app ficam fora dessa troca. Se a ativação falhar, a instalação anterior é restaurada.

Cada instalação também grava `install/launch-config.json`, versão 1, com pacote, ABI, `Application`, Activity launcher, SDKs declarados e caminhos relativos para APK, assets e diretórios isolados. Se o manifesto declarar `android.app.lib_name`, o preparador normaliza o nome para `lib<nome>.so` e falha se essa biblioteca não existir na ABI extraída. Essa configuração é metadado de bootstrap, não inicia o app nem comprova que o launcher ou a biblioteca conseguem executar.

O preparador valida que cada biblioteca ARM64 é ELF64 AArch64 little-endian `ET_DYN`, com segmentos `PT_LOAD` e `PT_DYNAMIC`, antes de copiá-la. Também grava `install/native-load-plan-arm64-v8a.txt` com SONAME, intervalos virtuais alinhados por página, permissões, tamanho BSS e tipos/quantidades de relocations dinâmicas de cada `.so`. O SONAME ELF é usado junto ao nome do arquivo empacotado para corresponder dependências `DT_NEEDED`; identidades ambíguas são rejeitadas. Durante `prepare`, cada imagem é realmente mapeada em páginas RW anônimas, recebe os segmentos com BSS zerado e tenta aplicar relocations ARM64 dinâmicas `RELATIVE`, `ABS64/32/16`, `PREL64/32/16`, `GLOB_DAT` e `JUMP_SLOT`, validando largura, sinal, alvo gravável e estouro antes de efetivar qualquer escrita. Imports versionados são resolvidos apenas contra exports com a mesma versão e hash ELF; exports versionados não default não são usados por imports sem versão. Se o ELF declara versionamento que não pôde ser decodificado, os imports afetados permanecem pendentes, sem cair para uma resolução não versionada. Imports de bibliotecas empacotadas só podem resolver por exports na própria closure transitiva de `DT_NEEDED`, com dependências percorridas primeiro e definição forte prevalecendo sobre fraca. A ordem calculada e o resumo de relocations vão para `install/native-image-check-arm64-v8a.txt`; versões de imports estão no plano ELF. Os mapeamentos são liberados ao terminar a preparação, não recebem permissão de execução, símbolos Android ausentes ficam pendentes, e nenhuma rotina do APK é chamada. `install/native-dependencies-arm64-v8a.txt` classifica dependências fornecidas por outra `.so` do APK, dependências conhecidas da plataforma Android e dependências não classificadas; `install/native-symbols-arm64-v8a.txt` lista símbolos dinâmicos indefinidos agrupados por família. Isso ainda não é um carregador de produção nem prova que as bibliotecas podem executar.

O mapeador de caminhos reconhece `/storage/emulated/0`, `/storage/self/primary`, `/sdcard` e `/mnt/sdcard` como aliases do armazenamento compartilhado isolado. Também reconhece os dados privados em `/data/data/<pacote>`, `/data/user/0/<pacote>` e `/data/user_de/0/<pacote>`; cache e arquivos privados são direcionados aos diretórios `cache/` e `files/`, preferências e bancos permanecem em `data/`, e o caminho `user_de` vai para `data_de/`. Os diretórios específicos de outro pacote sob `Android/data`, `Android/obb` ou `Android/media` são recusados. Assim, `/storage/emulated/0/Delta` continua correspondendo a `<diretório-de-dados>/com.roblox.client/storage/Delta`, sem criar ou escrever em `/android` ou na raiz do host. Esse mapeador ainda é uma função de resolução lexical; a futura camada que abrir arquivos também deverá impor isolamento contra symlinks.

Esta etapa **não inicia o app**: ainda faltam carregador compatível com Bionic, ART/JNI, APIs do framework Android, gráficos, áudio e mídia. O comando valida e extrai arquivos; não executa bibliotecas do APK.

## Relatório atual

- Decodificação do manifesto binário para pacote, classe `Application`, launcher, SDK mínimo/alvo, componentes, permissões, recursos e metadados.
- Inventário de arquivos multidex, métodos com o modificador DEX `native`, chamadas a APIs Java/Android e namespaces mais referenciados.
- Priorização das 20 referências de métodos Java/Android mais frequentes no DEX, para orientar o levantamento inicial das APIs necessárias; `--symbols` continua exibindo a listagem completa.
- Contagem e priorização separadas das chamadas `android.*`, sem deixar APIs padrão de Java dominarem a lista de necessidades do framework Android.
- Comparação estática de classe, nome e descritor de parâmetros dos métodos DEX `native` com exports JNI `Java_*`, sinalizando bibliotecas com `JNI_OnLoad`.
- Detecção de chamadas DEX a `System.loadLibrary`, `System.load` e `Runtime.load`; resolve o argumento quando uma instrução `const-string` imediatamente anterior alimenta o registrador do argumento, mantendo strings restantes como candidatas.
- Recursos de hardware (`uses-feature`) e bibliotecas Android nativas declaradas no manifesto.
- Bibliotecas `.so` em `lib/<abi>/`, dependências `NEEDED` e agrupamento de imports de APIs Android/NDK.
- Classe ELF, arquitetura, compatibilidade entre arquitetura e ABI, e dependências `NEEDED`.
- Preparação valida ELF ARM64 e registra a classificação das dependências nativas do APK.
- A preparação gera um inventário dos símbolos ELF importados, agrupados por biblioteca e família de API.
- Imports/exports ELF e indicadores JNI como `JNI_OnLoad` e exports `Java_*`.
- Com `--symbols`, tentativa de decodificar nomes de classe/método dos exports JNI convencionais.

Limites de análise: 512 MiB por biblioteca, 256 MiB por DEX e 16 MiB para o manifesto. A varredura DEX percorre instruções `invoke-*`, mas ainda não interpreta fluxo de dados, reflexão, chamadas customizadas, código carregado dinamicamente ou caminhos condicionais. Um argumento de carregamento só é marcado como resolvido se o `const-string` imediatamente anterior escrever no registrador de argumento correto do `invoke`; em outros casos, strings do método permanecem candidatas, sem provar o valor passado. A associação DEX/JNI compara classe, nome e descritor de parâmetros quando o export contém o sufixo JNI de overload. Exports sem sufixo só são associados quando há um único método nativo com aquele nome na classe; sobrecargas são reportadas como ambíguas. O scanner não descobre registros dinâmicos `RegisterNatives`. Um `JNI_OnLoad` é apenas um indicador de possível inicialização JNI, não prova que o método foi registrado.

No APK atualmente analisado, a comparação encontrou correspondência convencional para 684 dos 733 métodos `native`: 5 por descritor exato de overload e 679 por export de nome curto sem sobrecarga nativa com o mesmo nome. Outros 49 não tiveram correspondência direta; três bibliotecas exportam `JNI_OnLoad`. Em 4 das 9 chamadas detectadas a carregadores, foi possível resolver o argumento direto e associá-lo a uma `.so` ARM64 presente no APK; as demais continuam sem argumento comprovado. A análise só resolve argumentos quando `const-string` grava diretamente no registrador passado ao `invoke`; strings do mesmo método sem essa forma permanecem como candidatas. Esses valores são resultados estáticos do APK e não confirmam quais métodos/caminhos executam nem como os registros dinâmicos funcionam. Para ver descritores e associações por método, use `--symbols`.

Este relatório estático é um mapa inicial das dependências visíveis, não uma lista completa de tudo que o runtime terá de implementar. Serviços solicitados em tempo de execução, comportamento de bibliotecas fechadas, recursos do dispositivo, autenticação e fluxos de rede não podem ser inferidos integralmente só do APK. A ferramenta não tenta contornar verificações de integridade, DRM ou autenticação.

## Resultado da análise de `J:\Temp\app\app.apk`

Última análise estática registrada:

- Aplicativo `com.roblox.client`, `RobloxApplication`, SDK mínimo 26 e alvo 35; 74 componentes, 30 permissões e 8 recursos de hardware declarados.
- O metadado `android.app.lib_name=roblox` indica que a Activity nativa solicita `libroblox.so`.
- Quatro DEX contêm 733 declarações de métodos `native`; a varredura reconheceu 190.969 call sites para 6.116 referências únicas a métodos Java/Android e 1.013 classes do framework.
- As áreas de API Java mais referenciadas incluem `android.view`, `android.graphics`, `android.app`, `android.content`, `android.os`, `android.media` e `android.hardware`, além de `java.util`, `java.lang`, `java.io` e `java.security`.
- O manifesto declara câmera, acelerômetro, giroscópio, touchscreen e microfone. As permissões incluem rede, câmera, gravação de áudio, notificações, armazenamento, contatos e billing.
- O APK empacota oito bibliotecas ARM64. `libroblox.so` depende de `libandroid`, `liblog`, `libOpenMAXAL`, `libmediandk`, `libGLESv2`, `libEGL`, `libOpenSLES`, `libdl`, `libm` e `libc`. Seus imports incluem 17 símbolos EGL, 74 OpenGL ES, 23 Media NDK, 15 de assets/configuração, 7 de looper/frame callbacks, 5 de janela nativa e 4 de logging.
- Chamadas DEX também sugerem carregamento de `renderscript-toolkit`, `image_processing_util_jni`, `surface_util_jni` e `backtrace-native`. Strings `robloxwebrtc` e `android_app_settings` e chamadas `System.load` permanecem sem associação comprovada a uma biblioteca incluída.

Os totais de chamadas são referências estáticas no conjunto de DEX, não prova de que cada caminho será executado em uma sessão. A lista de permissões é declarativa; o runtime precisaria implementar os serviços usados de fato, e não conceder automaticamente todos eles.

## Organização

```text
src/
  main.rs           # CLI do inspetor
  lib.rs            # módulos compartilhados
  bin/
    prbx-runtime.rs # CLI inicial de preparação do runtime
  runtime.rs        # isolamento de arquivos e preparação do APK
  apk.rs            # leitura do contêiner APK/ZIP e inventário de entradas
  analysis/
    manifest.rs     # parser de AndroidManifest.xml binário
    dex.rs          # declarações native e chamadas visíveis no bytecode DEX
  elf.rs            # metadados ELF, imports, exports e dependências
  jni.rs            # classificação e leitura estática de exports JNI
```

## Alvo de teste e arquitetura futura

Para uma VM de desenvolvimento comum, a recomendação inicial é **Ubuntu 24.04 LTS x86-64**. Ela é prática de virtualizar num PC x86-64 e já permite testar o CLI, a instalação isolada e o mapeamento de arquivos. O APK analisado, porém, traz `.so` somente para `arm64-v8a`; portanto, a VM x86-64 não pode executar essas bibliotecas diretamente. O preparador atual também não tenta fazê-lo.

Para iniciar a execução nativa do APK, Linux AArch64 continua sendo o caminho mais simples, pois evita tradução de instruções. Depois, o projeto poderá adicionar suporte x86-64 por tradução AArch64→x86-64, além do suporte nativo AArch64; isso será uma etapa separada e não resolve as APIs Android. Em ambas as arquiteturas ainda faltam Bionic, ART/JNI, framework, gráficos, áudio e mídia.

## Etapa JNI: escopo e limite

`src/analysis/dex.rs` e `src/jni.rs` fazem inventário estático de declarações e exports JNI. Isso ajuda a levantar classes e métodos nativos convencionais, mas **não implementa uma Java VM nem ART**. A crate `jni` normalmente conecta código nativo a uma VM já existente; não substitui a VM nem o framework Android.

Antes de implementar uma ponte de execução, é preciso identificar as classes Java/Kotlin e chamadas de framework do APK, inclusive os registros `RegisterNatives` realizados em `JNI_OnLoad`. Essa etapa exige analisar o bytecode DEX e o fluxo de inicialização. Um runtime real também precisará de uma implementação compatível de JNI e de serviços Android; retornar valores fictícios para chamadas não implementadas pode causar falhas difíceis de diagnosticar.
