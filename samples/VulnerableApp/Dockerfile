FROM mcr.microsoft.com/dotnet/sdk:latest AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:6.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_ENVIRONMENT=Development
ENV DB_PASSWORD=Pr0d!Passw0rd2024
ENTRYPOINT ["dotnet", "VulnerableApp.dll"]
