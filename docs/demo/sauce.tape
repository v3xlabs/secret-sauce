Output raw.mp4
Set Shell bash
Set FontFamily "Monocraft"
Set FontSize 36
Set LineHeight 1.31
Set Width 1956
Set Height 696
Set Padding 32
Set Framerate 25
Set TypingSpeed 8ms
Set Theme { "name": "mc", "black": "#1b1b24", "red": "#ff5555", "green": "#55ff55", "yellow": "#ffff55", "blue": "#7f9bff", "magenta": "#ff55ff", "cyan": "#55ffff", "white": "#e6e6e6", "brightBlack": "#8a8a9c", "brightRed": "#ff7777", "brightGreen": "#77ff77", "brightYellow": "#ffff77", "brightBlue": "#9fb4ff", "brightMagenta": "#ff77ff", "brightCyan": "#77ffff", "brightWhite": "#ffffff", "background": "#1b1b24", "foreground": "#e6e6e6", "selection": "#44445a", "cursor": "#55ff55" }
Hide
Type "cd ../repo/example && export SAUCE_IDENTITY=snakeoil/admin.key PS1='\[\e[32m\]example\[\e[0m\] $ '"
Enter
Sleep 400ms
Ctrl+L
Sleep 300ms
Show
Sleep 400ms

Type "sauce generate"
Enter
Wait+Screen /Generated:/
Sleep 1500ms
Hide
Ctrl+L
Sleep 300ms
Show
Sleep 300ms

Type "sauce set ddclient/api-token --expires 2027-05-15"
Enter
Wait+Screen /Value of ddclient\/api-token/
Sleep 500ms
Type "not-a-real-token"
Sleep 150ms
Enter
Wait+Screen /set ddclient\/api-token, version 1/
Sleep 1500ms
Hide
Ctrl+L
Sleep 300ms
Show
Sleep 300ms

Type "sauce rotate 'sso/*'"
Enter
Wait+Screen /Rotate them/
Sleep 400ms
Type "y"
Sleep 240ms
Enter
Wait+Screen /rotated sso\/miniflux/
Sleep 1500ms
