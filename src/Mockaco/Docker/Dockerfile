FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
EXPOSE 5000

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
COPY ./src/Mockaco/Mockaco.csproj /src/Mockaco/
WORKDIR /src/Mockaco
RUN dotnet restore
WORKDIR /repo
COPY ./ ./
WORKDIR /repo/src/Mockaco
RUN dotnet publish "Mockaco.csproj" -c Release -o /app/publish

FROM base AS final
ENV ASPNETCORE_ENVIRONMENT=Docker
WORKDIR /app
COPY --from=build /app/publish .
VOLUME /app/Profiles
VOLUME /app/Settings
ENTRYPOINT ["dotnet", "Mockaco.dll"]