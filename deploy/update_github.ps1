param(
    [string]$Message = "Update project",
    [string]$Branch = "main"
)

git add .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

git commit -m $Message
if ($LASTEXITCODE -ne 0) {
    Write-Host "Nothing to commit or commit failed."
}

git push origin $Branch
exit $LASTEXITCODE
