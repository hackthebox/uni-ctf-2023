#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0-alpine-amd64 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:7.0-alpine-amd64 AS build
WORKDIR /src
COPY ["Nexus_Void/Nexus_Void.csproj", "Nexus_Void/"]
RUN dotnet restore "Nexus_Void/Nexus_Void.csproj"
COPY . .

WORKDIR "/src/Nexus_Void"
RUN dotnet tool install --global dotnet-ef --version 7.0.0
ENV PATH="$PATH:/root/.dotnet/tools"
RUN dotnet ef database update
RUN dotnet build "Nexus_Void.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Nexus_Void.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
COPY --from=build /src/Nexus_Void/Database.db .

RUN apk add --no-cache --update procps bash supervisor

RUN echo "top -bn1 | grep 'Cpu(s)' | awk '{print \$2 + \$4}' | tr -d '\\n'" > /tmp/cpu.sh
RUN echo "free -m | awk 'NR==2{printf \"%sMB\", \$3}'" > /tmp/mem.sh
RUN echo "df -h | awk '\$NF==\"/\"{printf \"%d/%dGB (%s)\", \$3, \$2, \$5}'" > /tmp/disk.sh

COPY flag.txt /flag.txt

COPY config/supervisord.conf /etc/supervisord.conf

EXPOSE 80

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]