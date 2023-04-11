import org.scalajs.linker.interface.ModuleSplitStyle

name := "paillier"
organization := "com.evoting"

version := "4.1.0"

lazy val scala213 = "2.13.6"

lazy val scala302 = "3.1.0"

lazy val catsCore = "2.7.0"

lazy val catsEffect = "3.3.0"

lazy val fs2 = "3.2.3"

// To publish in both scala version we do:  `sbt +publish`
crossScalaVersions := Seq(scala213, scala302)

initialize := {
  val _        = initialize.value // run the previous initialization
  val required = "11"
  val current  = sys.props("java.specification.version")
  assert(current == required, s"Unsupported JDK: java.specification.version $current != $required")
}

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest"                     % "3.2.10" % Test,
  "org.typelevel" %% "cats-effect-testing-scalatest" % "1.3.0"  % Test
)

lazy val paillier=project.in(file("."))
.enablePlugins(ScalaJSPlugin)
.settings(
  scalaVersion := "2.13.6",
  scalaJSUseMainModuleInitializer := true,

    /* Configure Scala.js to emit modules in the optimal way to
     * connect to Vite's incremental reload.
     * - emit ECMAScript modules
     * - emit as many small modules as possible for classes in the "livechart" package
     * - emit as few (large) modules as possible for all other classes
     *   (in particular, for the standard library)
     */
    scalaJSLinkerConfig ~= {
      _.withModuleKind(ModuleKind.ESModule)
        .withModuleSplitStyle(
          ModuleSplitStyle.SmallModulesFor(List("paillier")))
    },

    /* Depend on the scalajs-dom library.
     * It provides static types for the browser DOM APIs.
     */
    

    libraryDependencies ++=Seq(
  "org.scala-js"                      %%% "scalajs-dom"             % "2.4.0",
  "org.scala-js"                      %% "scalajs-env-jsdom-nodejs" % "1.0.0",
  "com.raquo"                         %%% "laminar"                 % "15.0.0",
  "com.raquo"                         %%% "airstream"               % "15.0.0",
  "com.raquo"                         %%% "domtypes"                % "17.0.0",
  "com.github.japgolly.scalajs-react" %%% "core"                    % "2.1.1"),

  libraryDependencies += ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13),
  libraryDependencies += "org.scalameta" %%% "munit" % "0.7.29" % Test,


 jsEnv := new org.scalajs.jsenv.nodejs.NodeJSEnv(),


libraryDependencies ++= Seq(
  "org.typelevel" %%% "cats-core"            % catsCore,
  "org.typelevel" %%% "cats-effect"          % catsEffect,
  "co.fs2"        %%% "fs2-core"             % fs2,
  "co.fs2"        %%% "fs2-io"               % fs2,
  "co.fs2"        %% "fs2-reactive-streams" % fs2
)

)


//resolvers += Resolver.url("Evoting Resolver", url("s3://evoting-repo"))(Resolver.ivyStylePatterns)
/*enablePlugins(ScalaJSPlugin)
scalaVersion := "2.13.6"
scalaJSUseMainModuleInitializer := true

scalaJSLinkerConfig ~= {
      _.withModuleKind(ModuleKind.ESModule)
        .withModuleSplitStyle(
          ModuleSplitStyle.SmallModulesFor(List("com")))
    }
*/
Compile / packageSrc / publishArtifact := false
Compile / packageDoc / publishArtifact := false

publishMavenStyle := false

//resolvers += Resolver.url("Evoting Resolver", url("s3://evoting-repo"))(Resolver.ivyStylePatterns)

publishMavenStyle := false
//publishTo := Some(Resolver.url("Evoting Resolver", url("s3://evoting-repo"))(Resolver.ivyStylePatterns))
