# Arpanet Suite — Build & Execução Mobile Android (APK & PWA)

O Arpanet Suite foi desenhado nativamente com arquitetura **Mobile-First**: possui barra de navegação inferior (Bottom Navigation Bar) adaptada para polegar, toque com altura mínima de 48px, ícones vetoriais fluidos e suporte completo a PWA e empacotamento APK.

---

## Método 1: Instalação Instantânea no Celular (Sem necessidade de compilar APK)

A aplicação conta com `manifest.json` com ícones vetoriais de alta resolução:

1. Inicie o `arpanet.exe` no seu computador conectado na rede Wi-Fi local.
2. No seu celular Android, abra o Google Chrome, Brave ou Samsung Internet.
3. Acesse o endereço do computador na rede local (ex: `http://192.168.1.105:9731`).
4. Toque no menu do navegador (três pontinhos no canto superior direito) e selecione:
   - **"Instalar aplicativo"** ou **"Adicionar à tela inicial"**.
5. O ícone oficial do **Arpanet Suite** será fixado no seu launcher do Android, abrindo em tela cheia (modo `standalone`), sem a barra de endereços do navegador e com a experiência 100% nativa.

---

## Método 2: Gerar o APK com Capacitor / Android Studio

Se você quiser compilar o binário `.apk` para instalar diretamente no celular:

### Pré-requisitos na sua máquina:
1. Instalar o **[Android Studio](https://developer.android.com/studio)**.
2. Instalar o **Java JDK 17 ou 21**.

### Comandos para gerar o APK:
Abra o PowerShell na pasta `c:\Users\Rafae\Documents\net\android`:

```powershell
# 1. Instalar as dependências do Capacitor:
npm install

# 2. Inicializar a plataforma Android:
npx cap add android

# 3. Sincronizar os arquivos da pasta UI:
npx cap sync android

# 4. Abrir o projeto no Android Studio:
npx cap open android
```

5. No Android Studio aberto:
   - Aguarde o Gradle sincronizar os pacotes.
   - Vá no menu superior: **Build** &rarr; **Build Bundle(s) / APK(s)** &rarr; **Build APK(s)**.
   - O APK final será gerado na pasta `android/android/app/build/outputs/apk/debug/app-debug.apk`.
   - Transfira esse arquivo para o celular e toque nele para instalar!

---

## Método 3: Projeto Kotlin Nativo com WebView

Se preferir criar um projeto do zero no Android Studio em Kotlin:

```kotlin
// MainActivity.kt
package com.arpanet.suite

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            cacheMode = WebSettings.LOAD_DEFAULT
            allowFileAccess = true
        }

        webView.webViewClient = WebViewClient()
        // IP do seu computador rodando o backend Arpanet
        webView.loadUrl("http://192.168.1.100:9731")
    }
}
```
No `AndroidManifest.xml`, certifique-se de adicionar a permissão de internet:
```xml
<uses-permission android:name="android.permission.INTERNET" />
<application android:usesCleartextTraffic="true" ...>
```
