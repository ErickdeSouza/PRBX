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

Para `com.roblox.client`, o preparador cria `install/apk/base.apk`, `install/native/arm64-v8a/` e diretórios separados para `data/`, `cache/`, `files/` e `storage/Delta/`. O caminho Android `/storage/emulated/0/Delta` é mapeado para `<diretório-de-dados>/com.roblox.client/storage/Delta`. Essa árvore é isolada e não cria nem escreve em `/android` ou na raiz do host.

Esta etapa **não inicia o app**: ainda faltam carregador compatível com Bionic, ART/JNI, APIs do framework Android, gráficos, áudio e mídia. O comando valida e extrai arquivos; não executa bibliotecas do APK.

## Relatório atual

- Decodificação do manifesto binário para pacote, classe `Application`, launcher, SDK mínimo/alvo, componentes, permissões, recursos e metadados.
- Inventário de arquivos multidex, métodos com o modificador DEX `native`, chamadas a APIs Java/Android e namespaces mais referenciados.
- Detecção de chamadas DEX a `System.loadLibrary`, `System.load` e `Runtime.load`; strings no mesmo método são exibidas como candidatas e não como argumento comprovado.
- Recursos de hardware (`uses-feature`) e bibliotecas Android nativas declaradas no manifesto.
- Bibliotecas `.so` em `lib/<abi>/`, dependências `NEEDED` e agrupamento de imports de APIs Android/NDK.
- Classe ELF, arquitetura, compatibilidade entre arquitetura e ABI, e dependências `NEEDED`.
- Imports/exports ELF e indicadores JNI como `JNI_OnLoad` e exports `Java_*`.
- Com `--symbols`, tentativa de decodificar nomes de classe/método dos exports JNI convencionais.

Limites de análise: 512 MiB por biblioteca, 256 MiB por DEX e 16 MiB para o manifesto. A varredura DEX percorre instruções `invoke-*`, mas ainda não interpreta fluxo de dados, reflexão, chamadas customizadas, código carregado dinamicamente ou caminhos condicionais. As strings apresentadas perto de uma chamada de carregamento são pistas no método, não prova do valor passado. Os métodos `native` não são associados a `RegisterNatives` nem às bibliotecas que os implementam.

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
