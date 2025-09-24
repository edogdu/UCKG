const path = require('path')
const webpack = require('webpack')
const HtmlWebpackPlugin = require('html-webpack-plugin')

module.exports = () => ({
  mode: 'none',
  entry: './frontend/index.jsx',
  module: {
    rules: [
      {
      test: /\.jsx$/, 
      exclude: /node_modules|dist/,
      use: 'babel-loader'
      },
      {
        test: /\.css$/i,
        use: ["style-loader", "css-loader"],
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './index.html',
    }),
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify()//process.env.NODE_ENV || 'development'
    }),
  ],
  resolve: {
    fallback: {
      process: require.resolve('process/browser')
    }
  }
})
