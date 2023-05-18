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


lazy val paillier=project.in(file("."))
.enablePlugins(ScalaJSPlugin)
.settings(
  scalaVersion := "2.13.6",  
  scalacOptions += "-Ymacro-annotations",
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
    

    libraryDependencies ++=Seq( "org.scala-js" %%% "scalajs-dom" % "2.4.0",
  "org.scala-js"                      %% "scalajs-env-jsdom-nodejs" % "1.0.0",
  "com.github.japgolly.scalajs-react" %%% "core-ext-cats"        % "2.1.1",
  "com.github.japgolly.scalajs-react" %%% "core-ext-cats_effect" % "2.1.1",
  "com.github.japgolly.scalajs-react" %%% "core"                    % "2.1.1"),

  

  libraryDependencies += "com.dedipresta" %%% "scala-crypto" % "1.0.0",

  libraryDependencies += "me.shadaj" %%% "slinky-core" % "0.7.3", // core React functionality, no React DOM
  libraryDependencies += "me.shadaj" %%% "slinky-web" % "0.7.3", // React DOM, HTML and SVG tags
  libraryDependencies += "me.shadaj" %%% "slinky-native" % "0.7.3", // React Native components
  libraryDependencies += "me.shadaj" %%% "slinky-hot" % "0.7.3", // Hot loading, requires react-proxy package
   // Interop with japgolly/scalajs-react

  libraryDependencies += ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13),
  libraryDependencies += "org.scalameta" %%% "munit" % "0.7.29" % Test,

  libraryDependencies ++= Seq(
  "org.scalatest" %%% "scalatest"                     % "3.2.10" % Test,
  "org.typelevel" %%% "cats-effect-testing-scalatest" % "1.3.0"  % Test
),


 jsEnv := new org.scalajs.jsenv.nodejs.NodeJSEnv(),


libraryDependencies ++= Seq(
  "org.typelevel" %%% "cats-core"            % catsCore,
  "org.typelevel" %%% "cats-effect"          % catsEffect,
  "co.fs2"        %%% "fs2-core"             % fs2,
  "co.fs2"        %%% "fs2-io"               % fs2,
  "co.fs2"        %% "fs2-reactive-streams" % fs2
),
   
)

