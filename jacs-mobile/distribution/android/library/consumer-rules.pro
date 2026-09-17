# UniFFI's JNA declarations are accessed through reflection and native symbols.
-keep class ai.hai.jacs.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.Structure { <fields>; }
-keepclassmembers class * implements com.sun.jna.Callback { *; }
