mkdir C:\wifiagent
cd C:\wifiagent

# 여기 폴더에 main.go, ui.html 파일을 저장
go mod init wifiagent
go get modernc.org/sqlite

go build -o wifiagent.exe
.\wifiagent.exe
