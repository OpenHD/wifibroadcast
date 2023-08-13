
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <getopt.h>

#include <iostream>
#include <optional>

#include "../src/Encryption.h"

/**
 * Generates a new tx rx keypair and saves it to file for later use.
 */
int main(int argc, char *const *argv) {
  int opt;
  std::optional<std::string> bind_phrase=std::nullopt;
  while ((opt = getopt(argc, argv, "b:")) != -1) {
    switch (opt) {
      case 'b':{
        bind_phrase=std::string(optarg);
      }
        break;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "wfb-keygen [-b bind_phrase,deterministic], if no bind phrase is specified, random keys are generated (non-deterministic) %s\n",
                argv[0]);
        exit(1);
    }
  }
  wb::KeyPairTxRx keyPairTxRx{};
  if(bind_phrase.has_value()){
    std::cout<<"Generating txrx keypair using bind phrase ["<<bind_phrase.value()<<"]"<<std::endl;
    keyPairTxRx=wb::generate_keypair_from_bind_phrase(bind_phrase.value());
  }else{
    std::cout<<"Generating random txrx keypair"<<std::endl;
    keyPairTxRx=wb::generate_keypair_random();
  }
  //auto keypair=wb::generate_keypair_from_bind_phrase("openhd");
  return wb::write_keypair_to_file(keyPairTxRx,"txrx.key");
}
