plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.tcpclient"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.tcpclient"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

android {
    // ... compileSdk, defaultConfig, etc ...

    // === BAGA BLOCUL ASTA AICI ===
    packaging {
        resources {
            // Ii zicem sa ignore fisierul care face scandal
            excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"

            // Daca mai ai erori cu LICENSE sau NOTICE, decomenteaza astea:
            // excludes += "META-INF/DEPENDENCIES"
            // excludes += "META-INF/LICENSE"
            // excludes += "META-INF/LICENSE.txt"
            // excludes += "META-INF/license.txt"
            // excludes += "META-INF/NOTICE"
            // excludes += "META-INF/NOTICE.txt"
            // excludes += "META-INF/notice.txt"
            // excludes += "META-INF/ASL2.0"
        }
    }
}

dependencies {

    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout)
    //implementation(files("C:/Users/Rares/Desktop/TCPClient/app/libs/ChatClasses.jar "))
    implementation(files("libs/chat-lib.jar"))
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)

    implementation("com.google.code.gson:gson:2.10.1")

    implementation(files("libs/bcprov-jdk18on-1.83.jar"))
    implementation(files("libs/bcpkix-jdk18on-1.83.jar"))

    implementation("androidx.room:room-runtime:2.6.1")
    annotationProcessor("androidx.room:room-compiler:2.6.1")

    // === SQLCIPHER (Criptare baza de date) ===
    // Asta face ca Room sa fie "Seif". Fara asta, oricine cu root vede cheile.
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")

    // Fix pentru SQLCipher pe Android modern
    implementation("androidx.sqlite:sqlite:2.4.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}