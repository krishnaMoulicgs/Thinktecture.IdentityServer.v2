USE [master]
GO
/****** Object:  Database [IdentityServerUsers]    Script Date: 05/19/2014 14:23:52 ******/
CREATE DATABASE [IdentityServerUsers] ON  PRIMARY 
( NAME = N'IdentityServerUsers', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\IdentityServerUsers.mdf' , SIZE = 2304KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'IdentityServerUsers_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\IdentityServerUsers_log.LDF' , SIZE = 768KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [IdentityServerUsers] SET COMPATIBILITY_LEVEL = 100
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [IdentityServerUsers].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [IdentityServerUsers] SET ANSI_NULL_DEFAULT OFF
GO
ALTER DATABASE [IdentityServerUsers] SET ANSI_NULLS OFF
GO
ALTER DATABASE [IdentityServerUsers] SET ANSI_PADDING OFF
GO
ALTER DATABASE [IdentityServerUsers] SET ANSI_WARNINGS OFF
GO
ALTER DATABASE [IdentityServerUsers] SET ARITHABORT OFF
GO
ALTER DATABASE [IdentityServerUsers] SET AUTO_CLOSE OFF
GO
ALTER DATABASE [IdentityServerUsers] SET AUTO_CREATE_STATISTICS ON
GO
ALTER DATABASE [IdentityServerUsers] SET AUTO_SHRINK OFF
GO
ALTER DATABASE [IdentityServerUsers] SET AUTO_UPDATE_STATISTICS ON
GO
ALTER DATABASE [IdentityServerUsers] SET CURSOR_CLOSE_ON_COMMIT OFF
GO
ALTER DATABASE [IdentityServerUsers] SET CURSOR_DEFAULT  GLOBAL
GO
ALTER DATABASE [IdentityServerUsers] SET CONCAT_NULL_YIELDS_NULL OFF
GO
ALTER DATABASE [IdentityServerUsers] SET NUMERIC_ROUNDABORT OFF
GO
ALTER DATABASE [IdentityServerUsers] SET QUOTED_IDENTIFIER OFF
GO
ALTER DATABASE [IdentityServerUsers] SET RECURSIVE_TRIGGERS OFF
GO
ALTER DATABASE [IdentityServerUsers] SET  ENABLE_BROKER
GO
ALTER DATABASE [IdentityServerUsers] SET AUTO_UPDATE_STATISTICS_ASYNC OFF
GO
ALTER DATABASE [IdentityServerUsers] SET DATE_CORRELATION_OPTIMIZATION OFF
GO
ALTER DATABASE [IdentityServerUsers] SET TRUSTWORTHY OFF
GO
ALTER DATABASE [IdentityServerUsers] SET ALLOW_SNAPSHOT_ISOLATION OFF
GO
ALTER DATABASE [IdentityServerUsers] SET PARAMETERIZATION SIMPLE
GO
ALTER DATABASE [IdentityServerUsers] SET READ_COMMITTED_SNAPSHOT OFF
GO
ALTER DATABASE [IdentityServerUsers] SET HONOR_BROKER_PRIORITY OFF
GO
ALTER DATABASE [IdentityServerUsers] SET  READ_WRITE
GO
ALTER DATABASE [IdentityServerUsers] SET RECOVERY FULL
GO
ALTER DATABASE [IdentityServerUsers] SET  MULTI_USER
GO
ALTER DATABASE [IdentityServerUsers] SET PAGE_VERIFY CHECKSUM
GO
ALTER DATABASE [IdentityServerUsers] SET DB_CHAINING OFF
GO
USE [IdentityServerUsers]
GO
/****** Object:  Table [dbo].[Applications]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Applications](
	[ApplicationId] [uniqueidentifier] NOT NULL,
	[ApplicationName] [nvarchar](235) NOT NULL,
	[Description] [nvarchar](256) NULL,
 CONSTRAINT [Applications_PK_dbo.Applications] PRIMARY KEY CLUSTERED 
(
	[ApplicationId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[__MigrationHistory]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[__MigrationHistory](
	[MigrationId] [nvarchar](255) NOT NULL,
	[Model] [image] NOT NULL,
	[ProductVersion] [nvarchar](32) NOT NULL,
 CONSTRAINT [__MigrationHistory_PK_dbo.__MigrationHistory] PRIMARY KEY CLUSTERED 
(
	[MigrationId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Users]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[UserId] [uniqueidentifier] NOT NULL,
	[ApplicationId] [uniqueidentifier] NOT NULL,
	[UserName] [nvarchar](50) NOT NULL,
	[IsAnonymous] [bit] NOT NULL,
	[LastActivityDate] [datetime] NOT NULL,
 CONSTRAINT [Users_PK_dbo.Users] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IDX_UserName] ON [dbo].[Users] 
(
	[UserName] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_ApplicationId] ON [dbo].[Users] 
(
	[ApplicationId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Roles]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Roles](
	[RoleId] [uniqueidentifier] NOT NULL,
	[ApplicationId] [uniqueidentifier] NOT NULL,
	[RoleName] [nvarchar](256) NOT NULL,
	[Description] [nvarchar](256) NULL,
 CONSTRAINT [Roles_PK_dbo.Roles] PRIMARY KEY CLUSTERED 
(
	[RoleId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_ApplicationId] ON [dbo].[Roles] 
(
	[ApplicationId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UsersInRoles]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UsersInRoles](
	[UserId] [uniqueidentifier] NOT NULL,
	[RoleId] [uniqueidentifier] NOT NULL,
 CONSTRAINT [UsersInRoles_PK_dbo.UsersInRoles] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_RoleId] ON [dbo].[UsersInRoles] 
(
	[RoleId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_UserId] ON [dbo].[UsersInRoles] 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Profiles]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Profiles](
	[UserId] [uniqueidentifier] NOT NULL,
	[PropertyNames] [nvarchar](4000) NOT NULL,
	[PropertyValueStrings] [nvarchar](4000) NOT NULL,
	[PropertyValueBinary] [image] NOT NULL,
	[LastUpdatedDate] [datetime] NOT NULL,
 CONSTRAINT [Profiles_PK_dbo.Profiles] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_UserId] ON [dbo].[Profiles] 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Memberships]    Script Date: 05/19/2014 14:23:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Memberships](
	[UserId] [uniqueidentifier] NOT NULL,
	[ApplicationId] [uniqueidentifier] NOT NULL,
	[Password] [nvarchar](128) NOT NULL,
	[PasswordFormat] [int] NOT NULL,
	[PasswordSalt] [nvarchar](128) NOT NULL,
	[Email] [nvarchar](256) NULL,
	[PasswordQuestion] [nvarchar](256) NULL,
	[PasswordAnswer] [nvarchar](128) NULL,
	[IsApproved] [bit] NOT NULL,
	[IsLockedOut] [bit] NOT NULL,
	[CreateDate] [datetime] NOT NULL,
	[LastLoginDate] [datetime] NOT NULL,
	[LastPasswordChangedDate] [datetime] NOT NULL,
	[LastLockoutDate] [datetime] NOT NULL,
	[FailedPasswordAttemptCount] [int] NOT NULL,
	[FailedPasswordAttemptWindowStart] [datetime] NOT NULL,
	[FailedPasswordAnswerAttemptCount] [int] NOT NULL,
	[FailedPasswordAnswerAttemptWindowsStart] [datetime] NOT NULL,
	[Comment] [nvarchar](256) NULL,
 CONSTRAINT [Memberships_PK_dbo.Memberships] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_ApplicationId] ON [dbo].[Memberships] 
(
	[ApplicationId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
CREATE NONCLUSTERED INDEX [IX_UserId] ON [dbo].[Memberships] 
(
	[UserId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
GO
/****** Object:  ForeignKey [Users_FK_dbo.Users_dbo.Applications_ApplicationId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[Users]  WITH CHECK ADD  CONSTRAINT [Users_FK_dbo.Users_dbo.Applications_ApplicationId] FOREIGN KEY([ApplicationId])
REFERENCES [dbo].[Applications] ([ApplicationId])
GO
ALTER TABLE [dbo].[Users] CHECK CONSTRAINT [Users_FK_dbo.Users_dbo.Applications_ApplicationId]
GO
/****** Object:  ForeignKey [Roles_FK_dbo.Roles_dbo.Applications_ApplicationId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[Roles]  WITH CHECK ADD  CONSTRAINT [Roles_FK_dbo.Roles_dbo.Applications_ApplicationId] FOREIGN KEY([ApplicationId])
REFERENCES [dbo].[Applications] ([ApplicationId])
GO
ALTER TABLE [dbo].[Roles] CHECK CONSTRAINT [Roles_FK_dbo.Roles_dbo.Applications_ApplicationId]
GO
/****** Object:  ForeignKey [UsersInRoles_FK_dbo.UsersInRoles_dbo.Roles_RoleId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[UsersInRoles]  WITH CHECK ADD  CONSTRAINT [UsersInRoles_FK_dbo.UsersInRoles_dbo.Roles_RoleId] FOREIGN KEY([RoleId])
REFERENCES [dbo].[Roles] ([RoleId])
GO
ALTER TABLE [dbo].[UsersInRoles] CHECK CONSTRAINT [UsersInRoles_FK_dbo.UsersInRoles_dbo.Roles_RoleId]
GO
/****** Object:  ForeignKey [UsersInRoles_FK_dbo.UsersInRoles_dbo.Users_UserId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[UsersInRoles]  WITH CHECK ADD  CONSTRAINT [UsersInRoles_FK_dbo.UsersInRoles_dbo.Users_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([UserId])
GO
ALTER TABLE [dbo].[UsersInRoles] CHECK CONSTRAINT [UsersInRoles_FK_dbo.UsersInRoles_dbo.Users_UserId]
GO
/****** Object:  ForeignKey [Profiles_FK_dbo.Profiles_dbo.Users_UserId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[Profiles]  WITH CHECK ADD  CONSTRAINT [Profiles_FK_dbo.Profiles_dbo.Users_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([UserId])
GO
ALTER TABLE [dbo].[Profiles] CHECK CONSTRAINT [Profiles_FK_dbo.Profiles_dbo.Users_UserId]
GO
/****** Object:  ForeignKey [Memberships_FK_dbo.Memberships_dbo.Applications_ApplicationId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[Memberships]  WITH CHECK ADD  CONSTRAINT [Memberships_FK_dbo.Memberships_dbo.Applications_ApplicationId] FOREIGN KEY([ApplicationId])
REFERENCES [dbo].[Applications] ([ApplicationId])
GO
ALTER TABLE [dbo].[Memberships] CHECK CONSTRAINT [Memberships_FK_dbo.Memberships_dbo.Applications_ApplicationId]
GO
/****** Object:  ForeignKey [Memberships_FK_dbo.Memberships_dbo.Users_UserId]    Script Date: 05/19/2014 14:23:53 ******/
ALTER TABLE [dbo].[Memberships]  WITH CHECK ADD  CONSTRAINT [Memberships_FK_dbo.Memberships_dbo.Users_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([UserId])
GO
ALTER TABLE [dbo].[Memberships] CHECK CONSTRAINT [Memberships_FK_dbo.Memberships_dbo.Users_UserId]
GO
