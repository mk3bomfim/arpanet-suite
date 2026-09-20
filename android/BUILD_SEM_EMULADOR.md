# Arpanet Suite — Build Android Leve (Sem Android Studio / Sem Emulador)

Quando a máquina não tem espaço em disco para os 15-30 GB exigidos pelo Android Studio e seus emuladores pesados, existem **3 alternativas diretas, leves e que não ocupam espaço**.

---

## Opção 1: WebAPK / Instalação Direta PWA (Consome 0 MB no PC)
Esta é a forma oficial recomendada pelo Google para apps web modernos. Transforma a interface num aplicativo instalado com ícone e tela cheia sem precisar compilar nada.

1. No computador, rode o `arpanet.exe` (como Administrador).
2. No celular Android (conectado na mesma rede Wi-Fi), abra o **Chrome** ou **Brave**.
3. Digite o IP do seu computador com a porta:
   ```text
   http://192.168.1.X:9731
   ```
4. O navegador detectará o arquivo `manifest.json`.
5. Toque nos **três pontos do Chrome (canto superior)** &rarr; **"Instalar aplicativo"** ou **"Adicionar à tela inicial"**.
6. **Resultado:** O Android gera um WebAPK nativo diretamente no seu aparelho. Ele ganha ícone próprio na gaveta de aplicativos, abre sem navegador, sem abas, e funciona como um app instalado nativo.

---

## Opção 2: PWABuilder (Gera APK real na nuvem — 0 MB no PC)
A Microsoft mantém uma ferramenta gratuita na nuvem que compila o APK para você sem precisar instalar Java nem SDK no computador:

1. Acesse **[pwabuilder.com](https://www.pwabuilder.com/)**.
2. Se seu computador estiver acessível via túnel (ex: Ngrok, Cloudflare Tunnel ou IP público), insira a URL.
3. Clique em **"Build My PWA"** &rarr; **Android** &rarr; **Download Package**.
4. Ele compila o arquivo `.apk` nos servidores deles na nuvem e entrega o arquivo pronto para download.
5. Copie o APK para o celular e instale.

---

## Opção 3: GitHub Actions (Compilação do APK no Cloud da GitHub)
Podemos criar um workflow do GitHub Actions no repositório. O servidor do GitHub (que já possui Java, Gradle e Android SDK instalados) compila o APK para você em 2 minutos e disponibiliza o download nos Artifacts ou Releases:

Crie o arquivo `.github/workflows/build-apk.yml`:
```yaml
name: Build Android APK

on: [push, workflow_dispatch]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Java 17
        uses: actions/setup-java@v4
        with:
          distribution: 'zulu'
          java-version: 17

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install Dependencies
        run: |
          cd android
          npm install
          npx cap add android
          npx cap sync android

      - name: Build APK with Gradle
        run: |
          cd android/android
          chmod +x gradlew
          ./gradlew assembleDebug

      - name: Upload APK Artifact
        uses: actions/upload-artifact@v4
        with:
          name: arpanet-suite-debug-apk
          path: android/android/app/build/outputs/apk/debug/app-debug.apk
```
Ao enviar o código ou clicar em **"Run workflow"** no GitHub, o APK é gerado gratuitamente nos servidores do GitHub e você baixa direto no celular.
