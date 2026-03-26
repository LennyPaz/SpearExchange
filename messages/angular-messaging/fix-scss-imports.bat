@echo off
echo Updating all SCSS imports to use _variables...

REM Update all component SCSS files
powershell -Command "(Get-Content 'src\app\messaging\components\chat-header\chat-header.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\chat-header\chat-header.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\connection-status\connection-status.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\connection-status\connection-status.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\conversations-list\conversations-list.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\conversations-list\conversations-list.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\cross-conversation-notification\cross-conversation-notification.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\cross-conversation-notification\cross-conversation-notification.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\message-input\message-input.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\message-input\message-input.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\messages-area\messages-area.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\messages-area\messages-area.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\components\typing-indicator\typing-indicator.component.scss') -replace '@import ''../../../../styles/variables'';', '@import ''../../../../styles/_variables'';' | Set-Content 'src\app\messaging\components\typing-indicator\typing-indicator.component.scss'"

REM Update messaging.component.scss
powershell -Command "(Get-Content 'src\app\messaging\messaging.component.scss') -replace '@use ''../../../../styles/variables'' as \*;', '@import ''../../../styles/_variables'';' | Set-Content 'src\app\messaging\messaging.component.scss'"
powershell -Command "(Get-Content 'src\app\messaging\messaging.component.scss') -replace '@import ''../../../styles/variables'';', '@import ''../../../styles/_variables'';' | Set-Content 'src\app\messaging\messaging.component.scss'"

echo Done! All SCSS files updated.
pause
